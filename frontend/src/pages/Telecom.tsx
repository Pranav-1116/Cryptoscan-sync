import React, { useState } from "react";
import { Panel, Badge, PageHead, Stat } from "../components/ui.jsx";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useRealtime, useRealtimeRefresh } from "../lib/realtime.js";
import {
  apiTelecomPosture, apiTelecomRegistry, apiTelecomEvents,
  apiTelecomCarrierAdd, apiTelecomTargetAdd, apiTelecomScan,
  apiTelecomRoadmap, apiTelecomRoaming, apiTelecomPartnerAdd, downloadTelecomPack,
  apiTelecomJourney,
  TelecomPosture, TelecomRegistry, TelecomEventRec, TelecomRoamingRow, GroupRoadmap,
} from "../lib/api.js";

/* Telecom — realtime crypto posture of an international carrier estate.

   Carriers (PLMN/country/legal entity) → network functions (5G SBA, EPC,
   IMS, signaling, NDS/IP gateways) → live TLS probes classified against
   3GPP TS 33.210 / TS 33.501 and NIST SP 800-52r2 / IR 8547. Every scan
   pass diffs against the previous state; posture changes stream onto the
   platform event bus (SSE) and land in the live feed below. IPsec/IKE is
   classified from operator-side ingest — the scanner never fakes it. */

const SEV_TONE: Record<string, string> = {
  critical: "red", high: "red", medium: "amber", low: "amber", info: "green", ok: "green",
};

const num = (v: unknown): number => (typeof v === "number" ? v : 0);

export default function Telecom() {
  const rt = useRealtime();
  const lastDrift = rt.events.find((e) => e.type === "telecom.event");
  const posture = usePollingApi(apiTelecomPosture, 15000);
  const registry = usePollingApi(apiTelecomRegistry, 30000);
  const events = usePollingApi(apiTelecomEvents, 8000);
  const roadmap = usePollingApi(apiTelecomRoadmap, 60000);
  const roaming = usePollingApi(apiTelecomRoaming, 20000);
  const journey = usePollingApi(apiTelecomJourney, 15000);
  useRealtimeRefresh(posture.run, registry.run, events.run, roadmap.run, roaming.run, journey.run);

  const data: TelecomPosture | null = posture.data ?? null;
  const reg: TelecomRegistry | null = registry.data ?? null;
  const feed: TelecomEventRec[] = events.data?.events ?? [];

  const [carrier, setCarrier] = useState({ code: "", name: "", country: "", plmn: "", legal_entity: "" });
  const [target, setTarget] = useState({ nf_id: "", nf_type: "amf", endpoint: "", carrier_code: "" });
  const [partner, setPartner] = useState({ carrier_code: "", partner_plmn: "", partner_name: "", country: "" });

  const rmData: GroupRoadmap | null = roadmap.data ?? null;
  const roamingRows: TelecomRoamingRow[] = roaming.data?.rows ?? [];

  const addPartner = async () => {
    const r = await apiTelecomPartnerAdd(partner);
    if (r.source === "live") { setPartner({ carrier_code: "", partner_plmn: "", partner_name: "", country: "" }); registry.run(); roaming.run(); }
    else setScanMsg(`partner add failed: ${r.error}`);
  };
  const [scanning, setScanning] = useState(false);
  const [scanMsg, setScanMsg] = useState("");

  const rollup = data?.rollup ?? null;
  const totals = rollup?.totals ?? null;

  const addCarrier = async () => {
    const r = await apiTelecomCarrierAdd(carrier);
    if (r.source === "live") { setCarrier({ code: "", name: "", country: "", plmn: "", legal_entity: "" }); registry.run(); }
    else setScanMsg(`carrier add failed: ${r.error}`);
  };
  const addTarget = async () => {
    const r = await apiTelecomTargetAdd(target);
    if (r.source === "live") { setTarget({ ...target, nf_id: "", endpoint: "" }); registry.run(); }
    else setScanMsg(`target add failed: ${r.error}`);
  };
  const scanNow = async () => {
    setScanning(true); setScanMsg("");
    const r = await apiTelecomScan([], 4.0);
    setScanning(false);
    if (r.source === "live") {
      setScanMsg(`scanned ${r.data?.scanned ?? 0} NFs — ${r.data?.events?.length ?? 0} realtime events`);
      posture.run(); events.run();
    } else setScanMsg(`scan failed: ${r.error}`);
  };

  return (
    <>
      <PageHead
        crumb="scanners / telecom"
        title="Telecom realtime scanner"
        sub="international carrier estates — 5G SBA · EPC · IMS · signaling · NDS/IP, classified per 3GPP TS 33.210 / 33.501 + NIST 800-52r2"
        right={
          <>
            <button onClick={() => void scanNow()} disabled={scanning} style={{ padding: "4px 12px" }}>
              {scanning ? "Scanning…" : "Scan now"}
            </button>
            <span className="badge green"><span className="dot" /> CRYPTOSCAN_LIVE_TELECOM=1 → periodic</span>
          </>
        }
      />

      {scanMsg && <Panel title="Scan" sub={scanMsg} frame>{null}</Panel>}

      {data && !data.has_data && (
        <Panel title="No telecom scan yet" sub="register a carrier, add network functions, scan" frame>
          <p style={{ margin: 0, opacity: 0.75 }}>{data.message}</p>
        </Panel>
      )}

      {totals && (
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 4 }}>
          <Stat label="NF targets" value={num(totals.targets)} delta={`registered ${data?.targets_registered ?? totals.targets}`} />
          <Stat label="Reachable" value={num(totals.reachable)} tone={totals.unreachable ? "amber" : "green"} />
          <Stat label="Critical" value={num(totals.critical)} tone={num(totals.critical) ? "red" : "green"} />
          <Stat label="Expiring certs" value={num(totals.expiring_certs)} tone={num(totals.expiring_certs) ? "amber" : "green"} />
          <Stat label="PQC-ready SBI" value={num(totals.pqc_ready)} tone={num(totals.pqc_ready) ? "green" : ""} />
          <Stat label="Roaming edges" value={`${num(rollup?.roaming_edges.protected)}/${num(rollup?.roaming_edges.sepp_targets)} protected`}
            tone={num(rollup?.roaming_edges.unprotected) ? "red" : "green"} />
        </div>
      )}

      {totals && (
        <Panel title={`Estate posture — ${num(totals.targets)} NFs · worst ${totals.worst_severity}`} sub={`avg score ${totals.avg_score} · generated ${data?.generated_at?.slice(0, 19) ?? "—"}`} frame>
          <table style={{ borderCollapse: "collapse", width: "100%" }}>
            <thead>
              <tr>
                <th style={{ textAlign: "left", padding: "4px 8px" }}>Carrier</th>
                <th style={{ textAlign: "left", padding: "4px 8px" }}>PLMN</th>
                <th style={{ textAlign: "right", padding: "4px 8px" }}>NFs</th>
                <th style={{ textAlign: "right", padding: "4px 8px" }}>Critical</th>
                <th style={{ textAlign: "left", padding: "4px 8px" }}>Worst</th>
                <th style={{ textAlign: "left", padding: "4px 8px" }}>Entity</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(rollup?.by_carrier ?? {}).map(([code, c]) => (
                <tr key={code}>
                  <td style={{ padding: "4px 8px" }}>{c.name} <span style={{ opacity: 0.5 }}>({c.country})</span></td>
                  <td style={{ padding: "4px 8px" }}>{c.plmn}</td>
                  <td style={{ textAlign: "right", padding: "4px 8px" }}>{c.targets}</td>
                  <td style={{ textAlign: "right", padding: "4px 8px" }}>{c.critical}</td>
                  <td style={{ padding: "4px 8px" }}><Badge tone={SEV_TONE[c.worst_severity] || ""}>{c.worst_severity}</Badge></td>
                  <td style={{ padding: "4px 8px" }}>{c.legal_entity || "—"}</td>
                  <td style={{ padding: "4px 8px" }}>
                    <button onClick={() => void downloadTelecomPack(code, "json").catch(() => undefined)}
                      style={{ padding: "2px 8px", fontSize: "0.85em" }}>NRA pack</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {(rollup?.worst_targets ?? []).length > 0 && (
            <div style={{ marginTop: 8 }}>
              {(rollup?.worst_targets ?? []).map((w, i) => (
                <div key={i} style={{ marginBottom: 4 }}>
                  <Badge tone={SEV_TONE[w.severity] || ""}>{w.severity}</Badge>{" "}
                  <strong>{w.nf_id}</strong> <span style={{ opacity: 0.6 }}>({w.nf_type})</span> — {w.headline}
                </div>
              ))}
            </div>
          )}
        </Panel>
      )}

      <Panel title="Live event feed" sub="posture changes stream over the platform event bus (SSE)" frame>
        <div style={{ marginBottom: 8, fontSize: "0.92em" }}>
          <Badge tone={rt.conn === "live" ? "green" : "amber"}>{rt.conn}</Badge>{" "}
          {lastDrift ? (
            <span>
              last drift{" "}
              <strong>{String(lastDrift.payload?.kind ?? "")}</strong> on{" "}
              <strong>{String(lastDrift.payload?.nf_id ?? "")}</strong>{" "}
              <span style={{ opacity: 0.5 }}>({String(lastDrift.ts ?? "").slice(11, 19)})</span>
            </span>
          ) : (
            <span style={{ opacity: 0.55 }}>no drift observed since you opened this page</span>
          )}
        </div>
        {feed.length === 0 ? (
          <p style={{ margin: 0, opacity: 0.6 }}>No telecom events yet — run a scan, or enable the periodic scanner.</p>
        ) : (
          <div style={{ maxHeight: 260, overflowY: "auto" }}>
            {feed.map((e) => (
              <div key={e.id} style={{ marginBottom: 4 }}>
                <span style={{ opacity: 0.45 }}>{(e.ts || "").slice(11, 19)}</span>{" "}
                <Badge tone={SEV_TONE[e.payload?.severity] || ""}>{e.payload?.kind}</Badge>{" "}
                {e.payload?.message}
              </div>
            ))}
          </div>
        )}
      </Panel>

      {journey.data && journey.data.nf_tracked > 0 && (
        <Panel title="PQC adoption journey" sub="readiness eras per NF — every pass coalesces, a flip opens a new era" frame>
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 8 }}>
            <Stat label="Adoption" value={journey.data.adoption_pct === null ? "—" : `${journey.data.adoption_pct}%`}
              tone={journey.data.adoption_pct && journey.data.adoption_pct > 0 ? "green" : "amber"} />
            <Stat label="PQC-ready now" value={`${journey.data.pqc_ready_now}/${journey.data.nf_tracked}`} />
            <Stat label="Transitions" value={journey.data.transitions} />
          </div>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
            <thead>
              <tr style={{ textAlign: "start", opacity: 0.6 }}>
                <th style={{ padding: "4px 8px" }}>NF</th><th style={{ padding: "4px 8px" }}>now</th>
                <th style={{ padding: "4px 8px" }}>ready since</th><th style={{ padding: "4px 8px" }}>eras / flips</th>
                <th style={{ padding: "4px 8px" }}>passes</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(journey.data.per_nf).map(([nf, s]) => (
                <tr key={nf}>
                  <td style={{ padding: "4px 8px" }} className="mono">{nf}</td>
                  <td style={{ padding: "4px 8px" }}><Badge tone={s.pqc_ready ? "green" : "amber"}>{s.pqc_ready ? "hybrid PQC" : "classical"}</Badge></td>
                  <td style={{ padding: "4px 8px" }}>{(s.since ?? "").slice(0, 16).replace("T", " ")}</td>
                  <td style={{ padding: "4px 8px" }}>{s.eras} / {s.flips}</td>
                  <td style={{ padding: "4px 8px" }}>{s.passes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}

      {rmData && rmData.rows.length > 0 && (
        <Panel title="Migration roadmap — carrier estate" sub={rmData.basis} frame>
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 8 }}>
            <Stat label="Purge now" value={num(rmData.summary.instances_by_bucket.immediate)}
              tone={num(rmData.summary.instances_by_bucket.immediate) ? "red" : "green"} />
            <Stat label="Deprecated after 2030" value={num(rmData.summary.instances_by_bucket["by-2030"])}
              tone={num(rmData.summary.instances_by_bucket["by-2030"]) ? "amber" : "green"} />
            <Stat label="Disallowed after 2035" value={num(rmData.summary.instances_by_bucket["by-2035"])}
              tone={num(rmData.summary.instances_by_bucket["by-2035"]) ? "amber" : "green"} />
          </div>
          {rmData.rows.map((row, i) => (
            <div key={i} style={{ marginBottom: 3 }}>
              <Badge tone={SEV_TONE[row.bucket === "immediate" ? "critical" : row.bucket === "by-2030" ? "medium" : "low"] || ""}>{row.bucket}</Badge>{" "}
              <strong>{row.entity_name || row.entity_code}</strong> — {row.family} ×{row.instances} · {row.action}
            </div>
          ))}
        </Panel>
      )}

      <Panel title="Roaming partners" sub="inter-PLMN SBI protection per partner (GSMA IR.21 context · TS 33.501 SEPP)" frame>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 8, alignItems: "center" }}>
          <input placeholder="carrier (de-telekom)" value={partner.carrier_code} onChange={(e) => setPartner({ ...partner, carrier_code: e.target.value })}
            style={{ background: "none", border: "1px solid #233047", color: "inherit", padding: "4px 8px", borderRadius: 4, width: 150 }} />
          <input placeholder="partner PLMN (208-01)" value={partner.partner_plmn} onChange={(e) => setPartner({ ...partner, partner_plmn: e.target.value })}
            style={{ background: "none", border: "1px solid #233047", color: "inherit", padding: "4px 8px", borderRadius: 4, width: 160 }} />
          <input placeholder="partner name" value={partner.partner_name} onChange={(e) => setPartner({ ...partner, partner_name: e.target.value })}
            style={{ background: "none", border: "1px solid #233047", color: "inherit", padding: "4px 8px", borderRadius: 4, width: 150 }} />
          <input placeholder="country (fr)" value={partner.country} onChange={(e) => setPartner({ ...partner, country: e.target.value })}
            style={{ background: "none", border: "1px solid #233047", color: "inherit", padding: "4px 8px", borderRadius: 4, width: 90 }} />
          <button onClick={() => void addPartner()} disabled={!partner.carrier_code || !partner.partner_plmn || !partner.partner_name} style={{ padding: "4px 12px" }}>Add partner</button>
        </div>
        {roamingRows.length === 0 ? (
          <p style={{ margin: 0, opacity: 0.6 }}>No roaming partners registered.</p>
        ) : (
          <table style={{ borderCollapse: "collapse", width: "100%" }}>
            <thead>
              <tr>
                <th style={{ textAlign: "left", padding: "4px 8px" }}>Partner</th>
                <th style={{ textAlign: "left", padding: "4px 8px" }}>PLMN</th>
                <th style={{ textAlign: "left", padding: "4px 8px" }}>Country</th>
                <th style={{ textAlign: "left", padding: "4px 8px" }}>Inter-PLMN SBI</th>
                <th style={{ textAlign: "left", padding: "4px 8px" }}>SEPP</th>
                <th style={{ textAlign: "left", padding: "4px 8px" }}>PQC-ready</th>
              </tr>
            </thead>
            <tbody>
              {roamingRows.map((row) => (
                <tr key={row.id}>
                  <td style={{ padding: "4px 8px" }}>{row.partner_name}</td>
                  <td style={{ padding: "4px 8px" }}>{row.partner_plmn}</td>
                  <td style={{ padding: "4px 8px" }}>{row.country}</td>
                  <td style={{ padding: "4px 8px" }}>
                    <Badge tone={row.status === "protected" ? "green" : row.status === "unprotected" ? "red" : "amber"}>
                      {row.status}
                    </Badge>
                  </td>
                  <td style={{ padding: "4px 8px" }}>{row.sepp_nf_id || "—"}</td>
                  <td style={{ padding: "4px 8px" }}>
                    {row.status === "unknown" ? "—" : row.pqc_ready ? "yes" : "no"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title="Estate registry" sub="carriers (PLMN) and network functions — telecom.manage" frame>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 8, alignItems: "center" }}>
          <input placeholder="code (de-telekom)" value={carrier.code} onChange={(e) => setCarrier({ ...carrier, code: e.target.value })}
            style={{ background: "none", border: "1px solid #233047", color: "inherit", padding: "4px 8px", borderRadius: 4, width: 140 }} />
          <input placeholder="name" value={carrier.name} onChange={(e) => setCarrier({ ...carrier, name: e.target.value })}
            style={{ background: "none", border: "1px solid #233047", color: "inherit", padding: "4px 8px", borderRadius: 4, width: 150 }} />
          <input placeholder="country (de)" value={carrier.country} onChange={(e) => setCarrier({ ...carrier, country: e.target.value })}
            style={{ background: "none", border: "1px solid #233047", color: "inherit", padding: "4px 8px", borderRadius: 4, width: 80 }} />
          <input placeholder="plmn (262-01)" value={carrier.plmn} onChange={(e) => setCarrier({ ...carrier, plmn: e.target.value })}
            style={{ background: "none", border: "1px solid #233047", color: "inherit", padding: "4px 8px", borderRadius: 4, width: 90 }} />
          <input placeholder="entity (optional)" value={carrier.legal_entity} onChange={(e) => setCarrier({ ...carrier, legal_entity: e.target.value })}
            style={{ background: "none", border: "1px solid #233047", color: "inherit", padding: "4px 8px", borderRadius: 4, width: 110 }} />
          <button onClick={() => void addCarrier()} disabled={!carrier.code || !carrier.name} style={{ padding: "4px 12px" }}>Add carrier</button>
        </div>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 8, alignItems: "center" }}>
          <input placeholder="nf_id (amf-prod-01)" value={target.nf_id} onChange={(e) => setTarget({ ...target, nf_id: e.target.value })}
            style={{ background: "none", border: "1px solid #233047", color: "inherit", padding: "4px 8px", borderRadius: 4, width: 140 }} />
          <select value={target.nf_type} onChange={(e) => setTarget({ ...target, nf_type: e.target.value })}
            style={{ background: "#0b1220", border: "1px solid #233047", color: "inherit", padding: "4px 8px", borderRadius: 4 }}>
            {Object.entries(reg?.nf_catalog ?? {}).map(([id, spec]) => (
              <option key={id} value={id}>{id} — {spec.plane}</option>
            ))}
          </select>
          <input placeholder="host:port" value={target.endpoint} onChange={(e) => setTarget({ ...target, endpoint: e.target.value })}
            style={{ background: "none", border: "1px solid #233047", color: "inherit", padding: "4px 8px", borderRadius: 4, width: 190 }} />
          <input placeholder="carrier (optional)" value={target.carrier_code} onChange={(e) => setTarget({ ...target, carrier_code: e.target.value })}
            style={{ background: "none", border: "1px solid #233047", color: "inherit", padding: "4px 8px", borderRadius: 4, width: 130 }} />
          <button onClick={() => void addTarget()} disabled={!target.nf_id || !target.endpoint} style={{ padding: "4px 12px" }}>Add NF</button>
        </div>
        <div style={{ opacity: 0.7 }}>
          {reg ? `${reg.counts.carriers} carriers · ${reg.counts.targets} NF targets registered` : "registry offline"}
        </div>
      </Panel>
    </>
  );
}
