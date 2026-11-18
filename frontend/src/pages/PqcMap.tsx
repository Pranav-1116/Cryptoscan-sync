import { Link } from "react-router-dom";
import React, { useCallback, useEffect, useState } from "react";
import { Panel, Badge, Table, PageHead, Button } from "../components/ui.jsx";
import { useLive, LiveStatus } from "../lib/useLive.js";
import { writeFailure } from "../lib/requestFeedback.js";
import {
  apiPqcMigrationWorkspace, apiPqcMigrationCreateWave, apiPqcMigrationTransitionWave,
  apiPqcMigrationRecordProgress, apiPqcMigrationTransitionProgress,
  apiPqcMigrationRaiseBlocker, apiPqcMigrationTransitionBlocker,
  apiPqcMigrationRecordInterop,
  type PqcMigrationWorkspace,
} from "../lib/api.js";

/* PQC migration map (spec §21): live quantum-risk inventory by family +
   the deterministic migration waves. Candidate algorithms are the NIST
   FIPS 203/204 standards (real reference data); usage counts come only from
   the live inventory — never fabricated.
   Below it, the persisted plan register (api/routers/pqc_migration.py): waves,
   blockers, interoperability notes and verified progress. A recorded claim is
   not progress proven; verified is written only by a verification action with
   an evidence reference. */

interface Plan {
  inventory?: { total_sites?: number; vulnerable_sites?: number; pqc_ready_sites?: number; by_family?: Record<string, number>; by_threat_type?: Record<string, number> };
  waves?: Record<string, { focus?: string; site_count?: number }>;
  summary?: string;
}

const CANDIDATES = [
  { alg: "ML-KEM-768", use: "key encapsulation (FIPS 203)" },
  { alg: "ML-DSA-65", use: "digital signature (FIPS 204)" },
  { alg: "SLH-DSA", use: "stateless hash-based signature (FIPS 205)" },
];

function verdictTone(state: string): string {
  return state === "verified" || state === "cleared" ? "green"
    : state === "refuted" ? "red"
    : state === "open" ? "amber"
    : state === "stale" || state === "accepted" ? "amber" : "slate";
}

export function MigrationPlanRegister() {
  const [plan, setPlan] = useState<PqcMigrationWorkspace | null>(null);
  const [loadState, setLoadState] = useState<"loading" | "ok" | "failed">("loading");
  const [feedback, setFeedback] = useState("");
  const [waveKey, setWaveKey] = useState("");
  const [waveTitle, setWaveTitle] = useState("");
  const [waveTo, setWaveTo] = useState("");
  const [waveTarget, setWaveTarget] = useState("");
  const [claimWave, setClaimWave] = useState("");
  const [claimText, setClaimText] = useState("");
  const [claimEvidence, setClaimEvidence] = useState("");
  const [verifyId, setVerifyId] = useState("");
  const [verifyTo, setVerifyTo] = useState("verified");
  const [verifyEvidence, setVerifyEvidence] = useState("");
  const [blockerWave, setBlockerWave] = useState("");
  const [blockerTitle, setBlockerTitle] = useState("");
  const [blockerId, setBlockerId] = useState("");
  const [blockerTo, setBlockerTo] = useState("cleared");
  const [interopWave, setInteropWave] = useState("");
  const [interopPeer, setInteropPeer] = useState("");

  const reload = useCallback(async () => {
    const res = await apiPqcMigrationWorkspace();
    if (res.data) { setPlan(res.data); setLoadState("ok"); }
    else setLoadState("failed");
  }, []);
  useEffect(() => { void reload(); }, [reload]);

  const run = async (
    fn: () => Promise<{ data: unknown | null; error?: string }>,
    okText: string,
    clear?: () => void,
  ) => {
    const res = await fn();
    if (res.data) {
      setFeedback(okText);
      if (clear) clear();
      await reload();
    } else {
      const status = /HTTP (\d+)/.exec(res.error ?? "");
      setFeedback(writeFailure(status ? Number(status[1]) : undefined));
    }
  };

  const waves = plan?.waves ?? [];
  const blockers = plan?.blockers ?? [];
  const interop = plan?.interop ?? [];
  const progress = plan?.progress ?? [];

  return (
    <>
      <Panel
        title="Migration plan register"
        sub="persisted plan state — waves, blockers, interoperability, verified progress. A plan object is never estate state."
      >
        <div role="status" aria-live="polite" style={{ minHeight: 18, fontSize: 12, marginBottom: 8, color: feedback ? "var(--amber)" : "var(--dim)" }}>
          {feedback}
        </div>
        {loadState === "failed" && (
          <div className="dim" style={{ fontSize: 12.5 }}>
            <span title={"The plan register did not load. A failed read is a failure — never an empty plan."}>{"The plan register did not load."}</span>
          </div>
        )}
        {loadState === "ok" && waves.length === 0 && (
          <div style={{ fontSize: 12.5, color: "var(--dim)" }}>
            <strong>No migration waves registered.</strong> Absence of rows is absence of a plan — never a plan that is safe.
          </div>
        )}
        {waves.length > 0 && (
          <Table
            head={["wave", "title", "status", "window", "claims"]}
            rows={waves.map((w) => [
              <span className="mono" key={w.id}>{w.wave_key}</span>,
              w.title,
              <Badge tone={w.status === "verified" ? "green" : w.status === "blocked" ? "amber" : w.status === "active" ? "cyan" : "slate"} key={w.id}>{w.status}</Badge>,
              w.planned_window ?? "—",
              <span className="num" key={`${w.id}-c`}>{progress.filter((p) => p.wave_id === w.id).length}</span>,
            ])}
          />
        )}
        <div className="row" style={{ gap: 8, marginTop: 10, flexWrap: "wrap", alignItems: "center" }}>
          <input aria-label="new wave key" placeholder="wave key" value={waveKey} onChange={(e) => setWaveKey(e.target.value)} style={{ width: 110 }} />
          <input aria-label="new wave title" placeholder="title" value={waveTitle} onChange={(e) => setWaveTitle(e.target.value)} style={{ width: 200 }} />
          <Button onClick={() => run(
            () => apiPqcMigrationCreateWave({ wave_key: waveKey, title: waveTitle }),
            `wave ${waveKey || "?"} defined — planned, because a plan is never progress`,
            () => { setWaveKey(""); setWaveTitle(""); },
          )}>Define wave</Button>
          <input aria-label="transition wave key" placeholder="wave key" value={waveTarget} onChange={(e) => setWaveTarget(e.target.value)} style={{ width: 110 }} />
          <select aria-label="transition wave to" value={waveTo} onChange={(e) => setWaveTo(e.target.value)}>
            <option value="">move to…</option>
            {["planned", "active", "verified", "blocked", "superseded"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <Button onClick={() => run(
            () => apiPqcMigrationTransitionWave(waveTarget, { to: waveTo }),
            `wave ${waveTarget || "?"} -> ${waveTo || "?"}`,
          )}>Move wave</Button>
        </div>
      </Panel>

      <div className="grid cols-2 mt">
        <Panel title="Blockers" sub="raised explicitly, resolved explicitly — accepted is a recorded decision, never a silent close">
          {loadState === "ok" && blockers.length === 0 && (
            <div style={{ fontSize: 12.5, color: "var(--dim)" }}>No blockers registered. Absence of rows is not a clear path.</div>
          )}
          {blockers.length > 0 && (
            <Table
              head={["title", "state", "raised by", "resolution"]}
              rows={blockers.map((b) => [
                b.title,
                <Badge tone={verdictTone(b.state)} key={b.id}>{b.state}</Badge>,
                b.raised_by,
                b.resolution_note ?? "—",
              ])}
            />
          )}
          <div className="row" style={{ gap: 8, marginTop: 10, flexWrap: "wrap", alignItems: "center" }}>
            <input aria-label="blocker wave key" placeholder="wave key" value={blockerWave} onChange={(e) => setBlockerWave(e.target.value)} style={{ width: 110 }} />
            <input aria-label="blocker title" placeholder="blocker title" value={blockerTitle} onChange={(e) => setBlockerTitle(e.target.value)} style={{ width: 180 }} />
            <Button onClick={() => run(
              () => apiPqcMigrationRaiseBlocker(blockerWave, { title: blockerTitle }),
              `blocker raised on ${blockerWave || "?"} — open by construction`,
              () => setBlockerTitle(""),
            )}>Raise blocker</Button>
            <input aria-label="blocker id" placeholder="blocker id" value={blockerId} onChange={(e) => setBlockerId(e.target.value)} style={{ width: 130 }} />
            <select aria-label="blocker resolve to" value={blockerTo} onChange={(e) => setBlockerTo(e.target.value)}>
              {["cleared", "accepted", "open"].map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <Button onClick={() => run(
              () => apiPqcMigrationTransitionBlocker(blockerId, { to: blockerTo }),
              `blocker -> ${blockerTo}`,
            )}>Resolve</Button>
          </div>
        </Panel>

        <Panel title="Interoperability notes" sub="observations against peer systems — with their evidence, never inferred">
          {loadState === "ok" && interop.length === 0 && (
            <div style={{ fontSize: 12.5, color: "var(--dim)" }}>No interoperability notes recorded.</div>
          )}
          {interop.length > 0 && (
            <Table
              head={["peer", "protocol", "note", "evidence"]}
              rows={interop.map((n) => [
                n.peer_system, n.protocol || "—", n.note || "—",
                <span className="mono" key={n.id}>{n.evidence_ids.length ? n.evidence_ids.join(", ") : "none recorded"}</span>,
              ])}
            />
          )}
          <div className="row" style={{ gap: 8, marginTop: 10, flexWrap: "wrap", alignItems: "center" }}>
            <input aria-label="interop wave key" placeholder="wave key" value={interopWave} onChange={(e) => setInteropWave(e.target.value)} style={{ width: 110 }} />
            <input aria-label="interop peer" placeholder="peer system" value={interopPeer} onChange={(e) => setInteropPeer(e.target.value)} style={{ width: 180 }} />
            <Button onClick={() => run(
              () => apiPqcMigrationRecordInterop(interopWave, { peer_system: interopPeer }),
              `interop note recorded for ${interopPeer || "?"}`,
              () => setInteropPeer(""),
            )}>Record note</Button>
          </div>
        </Panel>
      </div>

      <Panel title="Progress claims" className="mt" sub="a recorded claim is not progress proven — verified is written only against an evidence reference">
        {loadState === "ok" && progress.length === 0 && (
          <div style={{ fontSize: 12.5, color: "var(--dim)" }}>No progress claims recorded.</div>
        )}
        {progress.length > 0 && (
          <Table
            head={["claim", "verdict", "recorded by", "evidence"]}
            rows={progress.map((p) => [
              p.claim,
              <span key={p.id}><Badge tone={verdictTone(p.verification_status)}>{p.verification_status}</Badge></span>,
              p.recorded_by,
              <span className="mono" key={`${p.id}-e`}>{p.evidence_ids.length ? p.evidence_ids.join(", ") : "none — unverified"}</span>,
            ])}
          />
        )}
        <div className="row" style={{ gap: 8, marginTop: 10, flexWrap: "wrap", alignItems: "center" }}>
          <input aria-label="claim wave key" placeholder="wave key" value={claimWave} onChange={(e) => setClaimWave(e.target.value)} style={{ width: 110 }} />
          <input aria-label="claim text" placeholder="progress claim" value={claimText} onChange={(e) => setClaimText(e.target.value)} style={{ width: 240 }} />
          <input aria-label="claim evidence ids" placeholder="evidence ids (comma)" value={claimEvidence} onChange={(e) => setClaimEvidence(e.target.value)} style={{ width: 170 }} />
          <Button onClick={() => run(
            () => apiPqcMigrationRecordProgress(claimWave, {
              claim: claimText,
              evidence_ids: claimEvidence.split(",").map((s) => s.trim()).filter(Boolean),
            }),
            "claim recorded — asserted, not yet checked",
            () => { setClaimText(""); setClaimEvidence(""); },
          )}>Record claim</Button>
          <input aria-label="verify record id" placeholder="claim id" value={verifyId} onChange={(e) => setVerifyId(e.target.value)} style={{ width: 130 }} />
          <select aria-label="verdict" value={verifyTo} onChange={(e) => setVerifyTo(e.target.value)}>
            {["verified", "refuted", "stale"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <input aria-label="verify evidence ids" placeholder="evidence ids (comma)" value={verifyEvidence} onChange={(e) => setVerifyEvidence(e.target.value)} style={{ width: 170 }} />
          <Button onClick={() => run(
            () => apiPqcMigrationTransitionProgress(verifyId, {
              to: verifyTo,
              evidence_ids: verifyEvidence.split(",").map((s) => s.trim()).filter(Boolean),
            }),
            `claim -> ${verifyTo}`,
            () => setVerifyEvidence(""),
          )}>Write verdict</Button>
        </div>
        <div className="dim" style={{ fontSize: 11.5, marginTop: 8 }}>
          verified requires an evidence reference — a verdict without evidence is refused.
        </div>
      </Panel>
    </>
  );
}

export default function PqcMap() {
  const { data, loading, error } = useLive<Plan>("/api/v1/quantum/plan", {});
  const inv = data.inventory ?? {};
  const byFamily = inv.by_family ?? {};
  const total = inv.total_sites ?? 0;
  const ready = inv.pqc_ready_sites ?? 0;
  const overall = total ? Math.round((ready / total) * 100) : 0;

  return (
    <>
      <PageHead
        crumb="post-quantum / pqc migration map"
        title="PQC migration map"
        sub="Current state → vulnerable inventory by family → candidate PQC → migration waves"
        right={<Badge tone="violet">OVERALL READINESS {overall}%</Badge>}
      />
      <div style={{ marginBottom: 12 }}><LiveStatus loading={loading} error={error} /></div>

      <Panel title="Migration path" sub="current quantum-vulnerable crypto → NIST PQC targets, phased in waves">
        {total > 0 ? (
          <div className="tree" style={{ fontSize: 13.5, lineHeight: 2.0 }}>
            {inv.vulnerable_sites} vulnerable of {total} inventoried sites<br />
            {"  ↓ wave 1 (HNDL critical/high): "}{data.waves?.["1"]?.site_count ?? 0} sites<br />
            {"  ↓ wave 2 (remaining Shor-vulnerable): "}{data.waves?.["2"]?.site_count ?? 0} sites<br />
            {"  ↓ wave 3 (Grover symmetric sizing): "}{data.waves?.["3"]?.site_count ?? 0} sites
          </div>
        ) : (
          <div className="dim" style={{ fontSize: 13.5 }}>
            No inventory yet. Run discovery and a scan; the map derives vulnerable families and migration
            waves from the live CBOM. Use the <Link to="/what-if">what-if simulator</Link> for a specific current → target transition.
          </div>
        )}
        {data.summary && <p className="dim" style={{ fontSize: 12.5, marginTop: 10 }}>{data.summary}</p>}
      </Panel>

      <div className="grid cols-3 mt">
        <Panel title="Vulnerable by family" sub="what must migrate (live inventory)">
          <Table
            head={["family", "usages"]}
            rows={Object.entries(byFamily).length
              ? Object.entries(byFamily).map(([fam, n]) => [fam.toUpperCase(), <span className="num" key={fam}>{n}</span>])
              : [["—", <span className="dim" key="e">no data until a scan runs</span>]]}
          />
        </Panel>
        <Panel title="Candidate algorithms" sub="NIST FIPS 203 / 204 / 205 standards — declared reference data, not estate observations">
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {CANDIDATES.map((c) => (
              <div key={c.alg}>
                <div className="spread" style={{ fontSize: 13.5 }}>
                  <span className="mono" style={{ fontWeight: 600 }}>{c.alg}</span>
                  <Badge tone="green">STANDARD</Badge>
                </div>
                <div className="dim" style={{ fontSize: 12 }}>{c.use}</div>
              </div>
            ))}
          </div>
        </Panel>
        <Panel title="Migration complexity" sub="per stage (deterministic guidance)">
          <Table
            head={["stage", "complexity"]}
            rows={[
              ["library upgrades", <Badge tone="green" key="1">LOW</Badge>],
              ["certificate re-key", <Badge tone="green" key="2">LOW</Badge>],
              ["protocol config", <Badge tone="amber" key="3">MEDIUM</Badge>],
              ["application code", <Badge tone="amber" key="4">MEDIUM</Badge>],
              ["HSM firmware", <Badge tone="red" key="5">HIGH</Badge>],
            ]}
          />
        </Panel>
      </div>

      <MigrationPlanRegister />

      <Panel title="Actions" className="mt">
        <div className="row">
          <Link to="/what-if" className="btn sm">Run what-if</Link>
          <Link to="/migration" className="btn sm">Open migration planner</Link>
        </div>
      </Panel>
    </>
  );
}
