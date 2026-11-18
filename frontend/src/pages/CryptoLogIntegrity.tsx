/* CryptoLog — Integrity monitor (docs/cryptolog/01_PRODUCT_SPEC.md §5, §9).
   Hash chains, checkpoints and verification, with the honesty the ledger
   guarantees on screen: VERIFIED only with a checkpoint whose signature
   checks out; a hash chain proves integrity relative to the trusted
   checkpoint — the original observation still needs source validation. */
import React, { useEffect, useState } from "react";
import { Badge, Panel } from "../components/ui.jsx";
import {
  apiCryptologCheckpoints, apiCryptologMerkleProof, apiCryptologVerify,
  type ApiResult, type CryptologCheckpoint, type CryptologMerkleProof,
  type CryptologVerifyResult,
} from "../lib/api.js";

const CONTROL_STYLE: React.CSSProperties = {
  padding: "6px 8px", borderRadius: 6, border: "1px solid var(--line)",
  background: "var(--panel)", color: "var(--ink)", fontSize: 12,
};

function describeIntegrityRead(result: ApiResult<unknown>, subject: string): string {
  const status = result.error?.match(/HTTP (\d{3})/)?.[1];
  if (status === "401") return `Authentication required to ${subject}. Sign in and try again.`;
  if (status === "403") return `Access denied to ${subject} for this account or tenant.`;
  return status ? `Unable to ${subject} (HTTP ${status}).` : `Unable to ${subject}; the service is offline or unreachable.`;
}

function stateTone(state: string): "green" | "red" | "violet" | "grey" {
  if (state === "VERIFIED") return "green";
  if (state === "TAMPERED" || state === "INVALID_HASH" || state === "CHAIN_BROKEN" || state === "SIGNATURE_INVALID") return "red";
  return "grey";
}

export default function CryptoLogIntegrity() {
  const [checkpoints, setCheckpoints] = useState<CryptologCheckpoint[]>([]);
  const [total, setTotal] = useState<number | null>(null);
  const [checkpointsFailure, setCheckpointsFailure] = useState<string | null>(null);
  const [session, setSession] = useState(0);

  const [verifyRef, setVerifyRef] = useState("");
  const [verifyResult, setVerifyResult] = useState<CryptologVerifyResult | null>(null);
  const [verifyFailure, setVerifyFailure] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);

  const [proofEventId, setProofEventId] = useState("");
  const [proofRef, setProofRef] = useState("");
  const [proof, setProof] = useState<CryptologMerkleProof | null>(null);
  const [proofFailure, setProofFailure] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setCheckpointsFailure(null);
    apiCryptologCheckpoints().then((result) => {
      if (!alive) return;
      if (!result.data) {
        setCheckpoints([]);
        setTotal(null);
        setCheckpointsFailure(describeIntegrityRead(result, "read the checkpoint register"));
        return;
      }
      setCheckpoints(result.data.rows);
      setTotal(result.data.total_count ?? result.data.rows.length);
    });
    return () => { alive = false; };
  }, [session]);

  const runVerify = () => {
    setVerifying(true);
    setVerifyFailure(null);
    setVerifyResult(null);
    apiCryptologVerify(verifyRef ? { checkpoint_ref: verifyRef } : {}).then((result) => {
      setVerifying(false);
      if (!result.data) {
        setVerifyFailure(describeIntegrityRead(result, "run integrity verification"));
        return;
      }
      setVerifyResult(result.data);
    });
  };

  const runProof = () => {
    setProofFailure(null);
    setProof(null);
    if (!proofEventId || !proofRef) {
      setProofFailure("An event id and a checkpoint ref are both required: a proof names what it proves.");
      return;
    }
    apiCryptologMerkleProof(proofEventId, proofRef).then((result) => {
      if (!result.data) {
        setProofFailure(describeIntegrityRead(result, "read this Merkle proof"));
        return;
      }
      setProof(result.data);
    });
  };

  return (
    <div data-testid="cryptolog-integrity" style={{ display: "grid", gap: 16 }}>
      <Panel title="Integrity monitor" sub="Hash chains, checkpoints and verification — VERIFIED is only ever reported with a checkpoint whose signature checks out">
        {checkpointsFailure ? (
          <div className="dim" data-testid="checkpoints-failure">
            {checkpointsFailure} A source that could not be read is not a register with no checkpoints.
          </div>
        ) : checkpoints.length === 0 ? (
          <div className="dim" data-testid="checkpoints-empty">
            <span title={"No checkpoints recorded yet. An absent checkpoint is not a verified chain — this screen never invents checkpoints."}>{"No checkpoints recorded yet."}</span>
          </div>
        ) : (
          <div data-testid="checkpoint-rows" style={{ display: "grid", gap: 6 }}>
            {checkpoints.map((cp) => (
              <div key={cp.checkpoint_ref} data-testid="checkpoint-row"
                style={{ textAlign: "left", padding: "8px 10px", borderRadius: 6, border: "1px solid var(--line)" }}>
                <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                  <strong style={{ fontSize: 13 }}>{cp.checkpoint_ref}</strong>
                  <Badge tone="grey">{cp.event_count ?? "?"} events</Badge>
                  <span className="dim" style={{ fontSize: 11 }}>
                    {cp.partition_id || "partition unrecorded"} · signer {cp.signer_id || "unrecorded"} · retention {cp.retention_ref || "unrecorded"}
                  </span>
                </div>
                <div className="dim" style={{ fontSize: 11, fontFamily: "var(--mono)" }}>
                  root {cp.merkle_root_hash ? `${cp.merkle_root_hash.slice(0, 16)}…` : "unrecorded"}
                  {cp.created_at ? ` · ${cp.created_at}` : ""}
                </div>
              </div>
            ))}
            <div className="dim" data-testid="checkpoints-total" style={{ fontSize: 11 }}>
              {checkpoints.length} shown{total !== null ? ` of ${total} recorded` : ""}.
            </div>
          </div>
        )}
      </Panel>

      <Panel title="Verification" sub="Recomputes hashes and the chain over the stored events; a failed read is a named failure, never a passed check">
        <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <input aria-label="verify checkpoint ref" placeholder="Checkpoint ref (optional)" value={verifyRef}
            onChange={(e) => setVerifyRef(e.target.value)} style={CONTROL_STYLE} />
          <button className="btn" data-testid="run-verify" onClick={runVerify} disabled={verifying}>
            {verifying ? "Verifying…" : "Run verification"}
          </button>
          <button className="btn" onClick={() => { setVerifyRef(""); setVerifyResult(null); setVerifyFailure(null); }}>Reset</button>
        </div>

        {verifyFailure ? (
          <div className="dim" data-testid="verify-failure" style={{ marginTop: 12 }}>{verifyFailure}</div>
        ) : verifyResult ? (
          <div data-testid="verify-result" style={{ marginTop: 12 }}>
            <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <Badge tone={stateTone(verifyResult.overall_state)}>{verifyResult.overall_state}</Badge>
              <span className="dim" style={{ fontSize: 11 }}>
                {verifyResult.input?.event_count ?? 0} events examined
                {verifyResult.input?.checkpoint_ref ? ` · checkpoint ${verifyResult.input.checkpoint_ref}` : " · no checkpoint requested"}
                {verifyResult.input?.checkpoint_signature_verified === true ? " · signature verified" : ""}
                {verifyResult.input?.checkpoint_signature_verified === false ? " · signature NOT verifiable" : ""}
              </span>
            </div>
            <div className="dim" data-testid="verify-note" style={{ marginTop: 8, fontSize: 12 }}>{verifyResult.note}</div>
            {verifyResult.results.length > 0 && (
              <ol data-testid="verify-entries" style={{ marginTop: 8, paddingLeft: 18, fontSize: 12, display: "grid", gap: 4 }}>
                {verifyResult.results.map((entry) => (
                  <li key={entry.event_id}>
                    {entry.event_id} — {entry.state}: {entry.note}
                  </li>
                ))}
              </ol>
            )}
          </div>
        ) : (
          <div className="dim" style={{ marginTop: 12, fontSize: 12 }}>
            <span title={"No verification run yet. Nothing on this screen is verified until it is verified."}>{"No verification run yet."}</span>
          </div>
        )}
      </Panel>

      <Panel title="Merkle proof" sub="Proves one event belongs to a checkpoint's batch — an event outside the window is a named absence, never a proof of nothing">
        <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <input aria-label="proof event id" placeholder="Event id" value={proofEventId}
            onChange={(e) => setProofEventId(e.target.value)} style={CONTROL_STYLE} />
          <input aria-label="proof checkpoint ref" placeholder="Checkpoint ref" value={proofRef}
            onChange={(e) => setProofRef(e.target.value)} style={CONTROL_STYLE} />
          <button className="btn" data-testid="run-proof" onClick={runProof}>Build proof</button>
          <button className="btn" onClick={() => { setProofEventId(""); setProofRef(""); setProof(null); setProofFailure(null); }}>Reset</button>
        </div>

        {proofFailure ? (
          <div className="dim" data-testid="proof-failure" style={{ marginTop: 12 }}>{proofFailure}</div>
        ) : proof ? (
          <div data-testid="proof-result" style={{ marginTop: 12, fontSize: 12 }}>
            <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <Badge tone={proof.verified ? "green" : "red"}>{proof.verified ? "PROOF VERIFIES" : "PROOF DOES NOT VERIFY"}</Badge>
              <span className="dim" style={{ fontSize: 11, fontFamily: "var(--mono)" }}>
                {proof.event_id} · leaf {proof.index} · hash {proof.event_hash.slice(0, 16)}…
              </span>
            </div>
            <div className="dim" style={{ marginTop: 8, fontFamily: "var(--mono)", fontSize: 11 }}>
              root {proof.merkle_root_hash} · {proof.proof.length} sibling step{proof.proof.length === 1 ? "" : "s"}
            </div>
          </div>
        ) : (
          <div className="dim" style={{ marginTop: 12, fontSize: 12 }}>
            No proof requested yet.
          </div>
        )}
      </Panel>
    </div>
  );
}
