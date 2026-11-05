import React, { useEffect, useState } from "react";
import { Panel, Badge } from "./ui.jsx";
import type { EstateTwinProtocolFloorDeclared } from "../lib/api.js";
import { apiEstateTwinProtocolFloor, type EstateTwinProtocolFloor } from "../lib/api.js";

/* ─── A protocol floor, checked against observed handshakes ──────────────────
   The question is an operator's, not an engineer's: "if we only accepted TLS 1.2
   from Friday, what is already below it?" The twin can answer the half it holds
   evidence for — the protocols endpoints actually negotiated — and must not answer
   the half it cannot see: a client that only offers TLS 1.0 is not an asset.

   So the panel has three published buckets, never two:
     below / at-or-above  the finding, from evidence
     unrecognised         a protocol value this build cannot rank — not compliance
     no evidence          assets with no handshake evidence — not compliance either
   and it prints the blind spots instead of letting silence read as safe.
──────────────────────────────────────────────────────────────────────────── */

const CHOICES = ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"];

const tone = (status: string) =>
  status === "BELOW_FLOOR_PRESENT" ? "red"
    : status === "BELOW_FLOOR_DECLARED" ? "amber"
      : status === "INSUFFICIENT_EVIDENCE" ? "amber"
        : "green";

export default function ProtocolFloorPanel({ initialFloor = "TLSv1.2" }: { initialFloor?: string }) {
  const [floor, setFloor] = useState(initialFloor);
  const [data, setData] = useState<EstateTwinProtocolFloor | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const check = async (value: string) => {
    setBusy(true);
    setError(null);
    const result = await apiEstateTwinProtocolFloor(value);
    if (result.ok) setData(result.data as EstateTwinProtocolFloor);
    else {
      setData(null);
      // a failed read is a fact about the read, not a clean estate
      setError("the floor check could not be read — that is not 'nothing is below the floor'");
    }
    setBusy(false);
  };

  useEffect(() => {
    void check(initialFloor);
    // one read on mount: the floor is a choice, and a choice re-asks
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const counts = data?.counts ?? {};

  return (
    <Panel
      title="Protocol floor"
      sub="if this were the weakest accepted protocol, what is already below it?"
      style={{ padding: "12px 14px" }}
    >
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center", marginBottom: 10 }}>
        {CHOICES.map((choice) => (
          <button
            key={choice}
            onClick={() => { setFloor(choice); void check(choice); }}
            aria-pressed={choice === floor}
            style={{
              padding: "4px 10px", borderRadius: 999, cursor: "pointer", fontSize: 11.5,
              fontFamily: "var(--mono)",
              background: choice === floor ? "color-mix(in srgb, var(--violet) 16%, transparent)" : "var(--panel-2)",
              border: `1px solid ${choice === floor ? "var(--violet)" : "var(--line)"}`,
              color: "var(--text)",
            }}
          >
            {choice}
          </button>
        ))}
        {busy && <Badge tone="slate">checking…</Badge>}
      </div>

      {error && <div style={{ fontSize: 11, color: "var(--red)" }}>{error}</div>}

      {data && (
        <>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center", marginBottom: 8 }}>
            <Badge tone={tone(data.status)}>{data.status}</Badge>
            <Badge tone="slate">{counts.protocol_records ?? 0} handshake records</Badge>
            <Badge tone="slate">{counts.assets_with_negotiated_evidence ?? 0} assets measured</Badge>
            {typeof counts.assets_without_negotiated_evidence === "number" && counts.assets_without_negotiated_evidence > 0 && (
              <Badge tone="amber">{counts.assets_without_negotiated_evidence} with no handshake evidence</Badge>
            )}
            {typeof counts.unrecognised === "number" && counts.unrecognised > 0 && (
              <Badge tone="amber">{counts.unrecognised} unrecognised</Badge>
            )}
          </div>

          {(data.below_floor ?? []).length > 0 && (
            <div style={{ overflowX: "auto" }}>
              <table className="tbl" style={{ width: "100%" }}>
                <thead><tr><th>Asset</th><th>Negotiated</th><th>Collector</th><th>Observed</th></tr></thead>
                <tbody>
                  {(data.below_floor ?? []).slice(0, 20).map((row, index) => (
                    <tr key={`${row.asset_id}-${row.evidence_id}-${index}`}>
                      <td style={{ fontSize: 11 }}>{row.asset_name ?? row.asset_id}</td>
                      <td style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--red)" }}>{String(row.negotiated)}</td>
                      <td style={{ fontSize: 11, color: "var(--faint)" }}>{row.collector ?? "—"}</td>
                      <td style={{ fontSize: 11 }}>{row.observed_at ? new Date(row.observed_at).toLocaleString() : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {(data.below_floor ?? []).length === 0 && data.status !== "INSUFFICIENT_EVIDENCE" && (
            <div style={{ fontSize: 11.5, color: "var(--dim)", lineHeight: 1.5 }}>
              No measured handshake is below {data.floor}. That is a statement about the handshakes the
              estate has observed — not about endpoints nobody has probed.
            </div>
          )}

          {data.status === "INSUFFICIENT_EVIDENCE" && (
            <div style={{ fontSize: 11.5, color: "var(--amber)", lineHeight: 1.5 }}>
              No evidence record in this estate carries a negotiated protocol, so nothing can be
              compared to this floor. That is a collection gap, not a clean result.
            </div>
          )}

          {(data.unrecognised ?? []).length > 0 && (
            <div style={{ marginTop: 8, fontSize: 11, color: "var(--dim)", lineHeight: 1.5 }}>
              {(data.unrecognised ?? []).slice(0, 5).map((row) => (
                <div key={`${row.asset_id}-${row.evidence_id}`}>
                  <b>{row.asset_name ?? row.asset_id}</b> reported{" "}
                  <span style={{ fontFamily: "var(--mono)" }}>{String(row.negotiated)}</span>, which this
                  build cannot rank. Unrecognised is not compliant.
                </div>
              ))}
            </div>
          )}

          <DeclaredAxis declared={data.declared} floor={data.floor ?? ""} />

          {data.note && <div style={{ marginTop: 8, fontSize: 11, color: "var(--faint)" }}>{data.note}</div>}

          {(data.blind_spots ?? []).length > 0 && (
            <details style={{ marginTop: 8 }}>
              <summary style={{ fontSize: 11, color: "var(--violet)", cursor: "pointer" }}>
                what this check cannot see ({data.blind_spots?.length})
              </summary>
              <ul style={{ margin: "6px 0 0", paddingLeft: 16, fontSize: 11, color: "var(--dim)", lineHeight: 1.6 }}>
                {(data.blind_spots ?? []).map((spot) => <li key={spot}>{spot}</li>)}
              </ul>
            </details>
          )}
        </>
      )}
    </Panel>
  );
}


/* ─── The declared axis ──────────────────────────────────────────────────────
   A TLS configuration that still lists TLSv1.0 is a finding, and it is not the
   same finding as a handshake that negotiated TLSv1.0. They are drawn apart, with
   the basis on the label, because an operator acting on one of them is doing a
   different piece of work than acting on the other.

   `edges: []` on a declared ceiling is printed as "nothing recorded on either side",
   not as "nothing would break".
──────────────────────────────────────────────────────────────────────────── */
function DeclaredAxis({
  declared, floor,
}: { declared?: EstateTwinProtocolFloorDeclared; floor: string }) {
  if (!declared || !declared.counts) return null;
  const below = declared.declares_below_floor ?? [];
  const ceiling = declared.declared_ceiling_below_floor ?? [];
  const unrankable = declared.declared_without_a_rankable_floor ?? [];
  const partial = declared.partially_parsed ?? [];
  const total = (declared.counts.declares_below_floor ?? 0)
    + (declared.counts.declared_ceiling_below_floor ?? 0)
    + (declared.counts.declared_without_a_rankable_floor ?? 0);
  if (total === 0 && partial.length === 0) return null;

  return (
    <div style={{ marginTop: 10, borderTop: "1px dashed var(--line)", paddingTop: 8 }}>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center", marginBottom: 6 }}>
        <Badge tone="violet">DECLARED</Badge>
        <span style={{ fontSize: 11, color: "var(--dim)" }}>
          what configurations allow — not what a handshake produced
        </span>
      </div>

      {below.length > 0 && (
        <div style={{ fontSize: 11, color: "var(--dim)", lineHeight: 1.6 }}>
          {below.slice(0, 10).map((row, index) => (
            <div key={`${row.asset_id}-${index}`}>
              <b>{row.asset_name ?? row.asset_id}</b> still permits{" "}
              <span style={{ fontFamily: "var(--mono)", color: "var(--amber)" }}>
                {(row.declared ?? []).length > 0
                  ? (row.declared ?? []).join(", ")
                  : row.declared_floor}
              </span>
              {row.partially_parsed && (
                <span style={{ color: "var(--faint)" }}> (config only partly parsed — there may be more)</span>
              )}
            </div>
          ))}
        </div>
      )}

      {ceiling.length > 0 && (
        <div style={{ marginTop: 6, fontSize: 11, color: "var(--dim)", lineHeight: 1.6 }}>
          {ceiling.slice(0, 10).map((row, index) => (
            <div key={`${row.asset_id}-${index}`}>
              <b>{row.asset_name ?? row.asset_id}</b> cannot reach {floor} at all (tops out at{" "}
              <span style={{ fontFamily: "var(--mono)", color: "var(--red)" }}>{row.declared_ceiling}</span>)
              {": "}
              {(row.edges ?? []).length > 0
                ? <>strands <span style={{ fontFamily: "var(--mono)" }}>{(row.edges ?? []).join(", ")}</span></>
                : <span style={{ color: "var(--faint)" }}>nothing recorded on either side of it</span>}
            </div>
          ))}
        </div>
      )}

      {unrankable.length > 0 && (
        <div style={{ marginTop: 6, fontSize: 11, color: "var(--dim)", lineHeight: 1.6 }}>
          {unrankable.slice(0, 5).map((row, index) => (
            <div key={`${row.asset_id}-${index}`}>
              <b>{row.asset_name ?? row.asset_id}</b> declares{" "}
              <span style={{ fontFamily: "var(--mono)" }}>{(row.unrecognised ?? []).join(", ")}</span> —
              not a version this build can rank, so not compliant either
            </div>
          ))}
        </div>
      )}

      {partial.length > 0 && (
        <div style={{ marginTop: 6, fontSize: 11, color: "var(--faint)" }}>
          {partial.length} configuration{partial.length === 1 ? "" : "s"} parsed only partly:{" "}
          {partial.slice(0, 5).map((row) => row.asset_name ?? row.asset_id).join(", ")}
        </div>
      )}

      <div style={{ marginTop: 6, fontSize: 10.5, color: "var(--faint)", lineHeight: 1.5 }}>
        {declared.meaning}
      </div>
    </div>
  );
}
