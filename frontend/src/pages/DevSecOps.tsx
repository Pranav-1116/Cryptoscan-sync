import React, { useState } from "react";
import { Panel, Badge, Table, PageHead, Code, Tabs } from "../components/ui.jsx";
import { ApiResult } from "../lib/api.js";
import {
  apiContainerScan, apiK8sScan, apiCloudPosture, apiSbomImport,
  apiSbomScan, apiSbomArtifacts, apiSbomValidate, apiSbomDiff, apiSbomVerify,
  apiSbomPrune, downloadSbomArtifact, downloadSbomReport,
  apiConnectorPreview,
} from "../lib/api.js";

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
function sevTone(s: string) { return s === "CRITICAL" ? "red" : s === "HIGH" ? "red" : s === "MEDIUM" ? "amber" : "green"; }

function FindingTable({ rows, codeKey, sevKey }: { rows: any[]; codeKey: (r: any) => string; sevKey: (r: any) => string }) {
  if (!rows?.length) return <p className="faint" style={{ fontSize: 12 }}>No findings — clean result.</p>;
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
  return (
    <Panel title="Container image scan (on push)" sub="Dockerfile policy + deterministic CVE match of installed packages against NVD-style feeds" className="mt">
      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 8 }}>
        <textarea className="inp" rows={4} value={dockerfile} onChange={(e) => setDockerfile(e.target.value)} style={{ fontFamily: "var(--mono)", fontSize: 11.5 }} placeholder="Dockerfile" />
        <textarea className="inp" rows={4} value={packages} onChange={(e) => setPackages(e.target.value)} style={{ fontFamily: "var(--mono)", fontSize: 11.5 }} placeholder='packages [{"name","version","ecosystem"}]' />
      </div>
      <textarea className="inp" rows={3} value={feed} onChange={(e) => setFeed(e.target.value)} style={{ fontFamily: "var(--mono)", fontSize: 11.5, marginBottom: 8 }} placeholder="advisory feed (NVD-style JSON)" />
      <button className="btn sm primary" onClick={() => void run()} disabled={busy}>{busy ? "Scanning…" : "Scan image"}</button>
      <div className="mt" style={{ marginBottom: 8 }}><Err res={res} /></div>
      {d && (
        <>
          <div className="row" style={{ gap: 8, marginBottom: 10 }}>
            <Badge tone={d.worst_severity === "CRITICAL" ? "red" : "green"}>{d.vulnerabilities} CVEs · worst {d.worst_severity}</Badge>
            <Badge tone={d.fixable ? "amber" : "green"}>{d.fixable} fixable</Badge>
            <Badge tone={d.dockerfile_findings.length ? "amber" : "green"}>{d.dockerfile_findings.length} Dockerfile issues</Badge>
          </div>
          <FindingTable rows={d.cve_matches.map((c: any) => ({ ...c, name: `${c.package}@${c.version}`, detail: `${c.cve_id}${c.fixed_version ? " → fix " + c.fixed_version : ""} (${c.ecosystem})` }))} codeKey={(r) => r.cve_id} sevKey={(r) => r.severity} />
          <div className="mt"><FindingTable rows={d.dockerfile_findings} codeKey={(r) => r.code} sevKey={(r) => r.severity} /></div>
        </>
      )}
    </Panel>
  );
}

/* ---- 14. K8s ---- */
function K8sPanel() {
  const [yaml, setYaml] = useState("apiVersion: v1\nkind: Pod\nmetadata:\n  name: example\nspec:\n  hostPID: true\n  containers:\n    - name: app\n      image: nginx:latest\n      securityContext:\n        privileged: true\n");
  const [res, setRes] = useState<ApiResult<any> | null>(null);
  const [busy, setBusy] = useState(false);
  const d = res?.data;
  return (
    <Panel title="Kubernetes manifest misconfig rules" sub="privileged pods, hostPath/hostPID, wildcards RBAC, missing limits/requests, run-as-root, latest image" className="mt">
      <textarea className="inp" rows={9} value={yaml} onChange={(e) => setYaml(e.target.value)} style={{ fontFamily: "var(--mono)", fontSize: 11.5, marginBottom: 8 }} />
      <button className="btn sm primary" onClick={async () => { setBusy(true); setRes(await apiK8sScan(yaml)); setBusy(false); }} disabled={busy}>{busy ? "Scanning…" : "Scan manifests"}</button>
      <div className="mt" style={{ marginBottom: 8 }}><Err res={res} /></div>
      {d && (
        <>
          <Badge tone={d.total_findings ? "red" : "green"}>{d.total_findings} findings across {d.manifests_scanned} manifest(s)</Badge>
          <div className="mt"><FindingTable rows={d.findings} codeKey={(r) => r.code} sevKey={(r) => r.severity} /></div>
        </>
      )}
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
  return (
    <Panel title="Cloud posture (CIS-style) — AWS / Azure / GCP" sub="public IAM, unencrypted/public buckets, open security groups, TLS, wildcard roles" className="mt">
      <textarea className="inp" rows={8} value={text} onChange={(e) => setText(e.target.value)} style={{ fontFamily: "var(--mono)", fontSize: 11.5, marginBottom: 8 }} />
      <button className="btn sm primary" onClick={async () => {
        setBusy(true);
        try { setRes(await apiCloudPosture(JSON.parse(text))); }
        catch (e) { setRes({ source: "live", ok: false, data: null, error: "JSON: " + String(e) }); }
        setBusy(false);
      }} disabled={busy}>{busy ? "Evaluating…" : "Evaluate posture"}</button>
      <div className="mt" style={{ marginBottom: 8 }}><Err res={res} /></div>
      {d && <><Badge tone={d.total_findings ? "red" : "green"}>{d.total_findings} findings / {d.resources_scanned} resources</Badge>
        <div className="mt"><FindingTable rows={d.findings} codeKey={(r) => r.rule_id} sevKey={(r) => r.severity} /></div></>}
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
  const [scanRes, setScanRes] = useState<ApiResult<any> | null>(null);
  const [scanning, setScanning] = useState(false);
  const [showBom, setShowBom] = useState(false);
  const [dlBusy, setDlBusy] = useState<string | null>(null);
  const scan = async () => {
    if (!target.trim()) { setScanRes({ source: "live", ok: false, data: null, error: "target is required" }); return; }
    setScanning(true); setShowBom(false);
    try {
      setScanRes(await apiSbomScan({ kind, target: target.trim(), format: fmt, as_image: asImage, include_vendored: includeVendored, use_lockfiles: useLockfiles }));
    } catch (e) { setScanRes({ source: "live", ok: false, data: null, error: String(e) }); }
    setScanning(false);
  };
  const m = scanRes?.data?.manifest;
  const compliance = scanRes?.data?.compliance;
  return (
    <Panel title="SBOM scanner — source tree / container → CycloneDX 1.5 · SPDX 2.3" sub="Walks manifests + lockfiles (resolved/transitive graph) or the container scanner, enriches crypto-relevant components with suppliers, checks pinning, and persists a signed artifact" className="mt">
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
      <button className="btn sm primary" onClick={() => void scan()} disabled={scanning}>{scanning ? "Scanning…" : "Scan & generate SBOM"}</button>
      <div className="mt" style={{ marginBottom: 8 }}><Err res={scanRes} /></div>
      {m && (
        <>
          <div className="row" style={{ gap: 8, marginBottom: 10, flexWrap: "wrap" }}>
            <Badge tone=""><span className="dot" /> {m.component_count} components</Badge>
            {kind === "source" && <Badge tone="">{m.direct_count} direct · {m.transitive_count} transitive{m.lockfile_count ? ` · ${m.lockfile_count} lockfiles` : ""}</Badge>}
            <Badge tone={m.crypto_components ? "blue" : ""}>{m.crypto_components} crypto-relevant</Badge>
            <Badge tone={m.unpinned ? "amber" : "green"}>{m.pinned} pinned / {m.unpinned} unpinned</Badge>
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
    </Panel>
  );
}

function SbomArtifactsTab() {
  const [artRes, setArtRes] = useState<ApiResult<any> | null>(null);
  const [busy, setBusy] = useState(false);
  const [rowBusy, setRowBusy] = useState<string | null>(null);
  const [verdicts, setVerdicts] = useState<Record<string, any>>({});
  const [pruneDays, setPruneDays] = useState(90);
  const [pruned, setPruned] = useState<string | null>(null);
  const refresh = async () => {
    setBusy(true);
    try { setArtRes(await apiSbomArtifacts()); }
    catch (e) { setArtRes({ source: "live", ok: false, data: null, error: String(e) }); }
    setBusy(false);
  };
  React.useEffect(() => { void refresh(); }, []);
  const arts = artRes?.data?.artifacts || [];
  const verify = async (id: string) => {
    setRowBusy(id);
    try {
      const res = await apiSbomVerify(id);
      setVerdicts((v) => ({ ...v, [id]: res.data || { verdict: res.error || "ERROR" } }));
    } finally { setRowBusy(null); }
  };
  return (
    <Panel title="SBOM artifacts — persisted, hash-signed" sub="Each artifact stores the exact bytes, their sha256, and an HMAC-SHA256 manifest signature; verify re-checks both. Reports summarise crypto inventory, pinning and minimum-elements status" className="mt">
      <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <button className="btn sm" onClick={() => void refresh()} disabled={busy}>{busy ? "Refreshing…" : "Refresh"}</button>
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
          head={["created", "format", "kind", "target", "components", "direct/trans", "NTIA", "provenance", ""]}
          rows={arts.map((a: any) => [
            String(a.created_at || "").replace("T", " ").slice(0, 19),
            a.format,
            a.kind,
            String(a.target || "").slice(0, 40),
            a.component_count,
            `${a.direct_count ?? "-"}/${a.transitive_count ?? "-"}`,
            a.minimum_elements || "-",
            verdicts[a.artifact_id]
              ? <Badge tone={verdicts[a.artifact_id].verdict === "OK" ? "green" : "red"}>{verdicts[a.artifact_id].verdict}</Badge>
              : <Badge tone={a.signature_alg ? "gray" : ""}>{a.signature_alg ? "signed" : "unsigned"}</Badge>,
            <span key={a.artifact_id} className="row" style={{ gap: 6 }}>
              <button className="btn sm" onClick={() => void verify(a.artifact_id)} disabled={rowBusy === a.artifact_id}>{rowBusy === a.artifact_id ? "…" : "Verify"}</button>
              <button className="btn sm" onClick={async () => { try { await downloadSbomReport(a.artifact_id); } catch (e) { window.alert("report failed: " + String(e)); } }}>Report</button>
              <button className="btn sm" onClick={async () => { try { await downloadSbomArtifact(a.artifact_id); } catch (e) { window.alert("download failed: " + String(e)); } }}>SBOM</button>
            </span>,
          ])}
        />
      ) : <div className="muted" style={{ fontSize: 12.5 }}>No artifacts yet — run a scan.</div>}
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
    <Panel title="SBOM diff — what changed between two bills of materials" sub="Components added/removed, version changes with upgrade/downgrade direction, license changes, and crypto-relevant deltas (supply-chain change review)" className="mt">
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
    <Panel title="SBOM validation — NTIA minimum elements" sub="Score a supplier's CycloneDX/SPDX document before accepting it: supplier, name, version, unique identifiers, dependency relationships, author, timestamp" className="mt">
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
    <Panel title="SBOM import — CycloneDX / SPDX + pinning" sub="Normalizes an incoming SBOM to the component model, checks version/digest pinning, and builds the dependency graph" className="mt">
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

function SbomPanel() {
  const [sub, setSub] = useState(0);
  const tabs = ["Scan & generate", "Artifacts", "Diff", "Validate", "Import"];
  return (
    <>
      <div className="mt"><Tabs tabs={tabs} active={sub} onChange={setSub} /></div>
      {sub === 0 && <SbomScanTab />}
      {sub === 1 && <SbomArtifactsTab />}
      {sub === 2 && <SbomDiffTab />}
      {sub === 3 && <SbomValidateTab />}
      {sub === 4 && <SbomImportTab />}
    </>
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
    <Panel title="Ticketing · SIEM · bus · chat connectors" sub="ServiceNow/Jira (dedup correlation keys), Splunk HEC & Elastic bulk, Kafka/RabbitMQ, Slack/Teams adaptive cards with ack/assign" className="mt">
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
  const tabs = ["Container scan", "K8s manifests", "Cloud posture", "SBOM", "Connectors"];
  return (
    <>
      <PageHead
        crumb="operate / devsecops pipeline"
        title="DevSecOps pipeline"
        sub="Container CVE scan on push · K8s misconfig rules · cloud CIS posture · CycloneDX/SPDX SBOM + pinning · ITSM/SIEM/bus/chat connectors — deterministic, fail-closed"
        right={<Badge tone=""><span className="dot" /> SHIFT-LEFT GATES</Badge>}
      />
      <div className="mt"><Tabs tabs={tabs} active={tab} onChange={setTab} /></div>
      {tab === 0 && <ContainerPanel />}
      {tab === 1 && <K8sPanel />}
      {tab === 2 && <PosturePanel />}
      {tab === 3 && <SbomPanel />}
      {tab === 4 && <ConnectorPanel />}
    </>
  );
}
