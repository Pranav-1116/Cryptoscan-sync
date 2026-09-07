import React, { useState } from "react";
import { Panel, Badge, Table, PageHead, Code, Tabs } from "../components/ui.jsx";
import { ApiResult } from "../lib/api.js";
import {
  apiContainerScan, apiK8sScan, apiCloudPosture, apiSbomImport,
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

/* ---- 16. SBOM ---- */
function SbomPanel() {
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
    <Panel title="SBOM import — CycloneDX / SPDX + pinning" sub="Normalizes an SBOM to the component model, checks version/digest pinning, and builds the dependency graph" className="mt">
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
