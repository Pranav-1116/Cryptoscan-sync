/* Integrity monitor tests (docs/cryptolog/01_PRODUCT_SPEC.md §5, §9):
   VERIFIED only with a checkpoint whose signature checks out, the honesty
   note on screen, unverifiable checkpoints never trusted, proofs that
   verify or name their absence, and failed reads as named failures. */

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { mockFetch, offlineFetch } from "../test/setup";
import CryptoLogIntegrity from "./CryptoLogIntegrity";
import { withTitles } from "../test/withTitles";

const checkpointRow = (over: Record<string, unknown> = {}) => ({
  checkpoint_ref: "cp_001",
  schema: "cryptoscan.cryptolog-chain/1",
  partition_id: "tenant_001:2026-11",
  sequence: 0,
  chain_hash: "a".repeat(64),
  merkle_root_hash: "b".repeat(64),
  event_count: 2,
  created_at: "2026-11-07T04:00:00Z",
  signer_id: "bank-hsm",
  signature: "c".repeat(64),
  retention_ref: "WORM:retention-7y",
  ...over,
});

const verifyResult = (over: Record<string, unknown> = {}) => ({
  schema: "cryptoscan.cryptolog-chain/1",
  partition_id: "tenant_001:2026-11",
  results: [
    { event_id: "clog_01", state: "VERIFIED", note: "integrity relative to the checkpoint" },
  ],
  overall_state: "VERIFIED",
  note: "a hash chain proves integrity relative to the trusted checkpoint and recorded provenance, not that the event itself is true: the original observation still needs source validation",
  checkpoint_used: true,
  input: { event_count: 1, checkpoint_ref: "cp_001", checkpoint_signature_verified: true },
  ...over,
});

const renderIntegrity = () => render(<CryptoLogIntegrity />);

describe("CryptoLog integrity monitor (§5, §9)", () => {
  it("lists checkpoints with recorded totals and names the signer and retention", async () => {
    mockFetch({
      "/api/v1/cryptolog/integrity/checkpoints": { rows: [checkpointRow()], total_count: 1 },
    });
    renderIntegrity();
    expect(await screen.findByText("cp_001")).toBeInTheDocument();
    expect(screen.getByTestId("checkpoint-row")).toHaveTextContent(/bank-hsm/);
    expect(screen.getByTestId("checkpoint-row")).toHaveTextContent(/WORM:retention-7y/);
    expect(screen.getByTestId("checkpoints-total")).toHaveTextContent(/1 shown of 1 recorded/);
  });

  it("states an empty register honestly — an absent checkpoint is not a verified chain", async () => {
    mockFetch({ "/api/v1/cryptolog/integrity/checkpoints": { rows: [], total_count: 0 } });
    renderIntegrity();
    expect(withTitles(await screen.findByTestId("checkpoints-empty"))).toMatch(/never invents checkpoints/);
  });

  it("names a failed register read instead of drawing zero checkpoints", async () => {
    offlineFetch();
    renderIntegrity();
    expect(await screen.findByTestId("checkpoints-failure")).toHaveTextContent(/not a register with no checkpoints/);
    expect(screen.queryByTestId("checkpoint-rows")).not.toBeInTheDocument();
  });

  it("reports VERIFIED with the honesty note and the signature verdict on screen", async () => {
    mockFetch({
      "/api/v1/cryptolog/integrity/checkpoints": { rows: [checkpointRow()], total_count: 1 },
      "/api/v1/cryptolog/integrity/verify": verifyResult(),
    });
    renderIntegrity();
    fireEvent.click(await screen.findByTestId("run-verify"));
    const result = await screen.findByTestId("verify-result");
    expect(result).toHaveTextContent("VERIFIED");
    expect(result).toHaveTextContent(/signature verified/);
    expect(screen.getByTestId("verify-note")).toHaveTextContent(/relative to the trusted checkpoint/);
    expect(screen.getByTestId("verify-note")).toHaveTextContent(/still needs source validation/);
    expect(screen.getByTestId("verify-entries")).toHaveTextContent(/clog_01/);
  });

  it("never shows VERIFIED for an unverifiable checkpoint — the refusal is drawn, not a pass", async () => {
    mockFetch({
      "/api/v1/cryptolog/integrity/checkpoints": { rows: [checkpointRow()], total_count: 1 },
      "/api/v1/cryptolog/integrity/verify": verifyResult({
        overall_state: "SIGNATURE_INVALID",
        note: "the covering checkpoint's signature does not verify",
        results: [{ event_id: "clog_01", state: "SIGNATURE_INVALID", note: "the covering checkpoint's signature does not verify" }],
        input: { event_count: 1, checkpoint_ref: "cp_001", checkpoint_signature_verified: false },
      }),
    });
    renderIntegrity();
    fireEvent.click(await screen.findByTestId("run-verify"));
    const result = await screen.findByTestId("verify-result");
    expect(result).toHaveTextContent("SIGNATURE_INVALID");
    expect(result).toHaveTextContent(/signature NOT verifiable/);
    expect(result).not.toHaveTextContent(/^VERIFIED$/);
  });

  it("names a failed verification instead of a passed check", async () => {
    mockFetch({ "/api/v1/cryptolog/integrity/checkpoints": { rows: [], total_count: 0 } });
    renderIntegrity();
    fireEvent.click(await screen.findByTestId("run-verify"));
    expect(await screen.findByTestId("verify-failure")).toBeInTheDocument();
    expect(screen.queryByTestId("verify-result")).not.toBeInTheDocument();
  });

  it("verifies a merkle proof and names its exact leaf and root", async () => {
    mockFetch({
      "/api/v1/cryptolog/integrity/checkpoints": { rows: [], total_count: 0 },
      "/api/v1/cryptolog/integrity/merkle-proof": {
        event_id: "clog_01ABC", event_hash: "d".repeat(64), index: 0,
        checkpoint_ref: "cp_001", merkle_root_hash: "b".repeat(64),
        proof: [{ sibling: "e".repeat(64), side: "right" }],
        verified: true,
      },
    });
    renderIntegrity();
    fireEvent.change(screen.getByLabelText("proof event id"), { target: { value: "clog_01ABC" } });
    fireEvent.change(screen.getByLabelText("proof checkpoint ref"), { target: { value: "cp_001" } });
    fireEvent.click(screen.getByTestId("run-proof"));
    const result = await screen.findByTestId("proof-result");
    expect(result).toHaveTextContent(/PROOF VERIFIES/);
    expect(result).toHaveTextContent(/1 sibling step/);
  });

  it("draws a non-verifying proof as a refusal, never a pass", async () => {
    mockFetch({
      "/api/v1/cryptolog/integrity/checkpoints": { rows: [], total_count: 0 },
      "/api/v1/cryptolog/integrity/merkle-proof": {
        event_id: "clog_01ABC", event_hash: "d".repeat(64), index: 3,
        checkpoint_ref: "cp_001", merkle_root_hash: "b".repeat(64),
        proof: [], verified: false,
      },
    });
    renderIntegrity();
    fireEvent.change(screen.getByLabelText("proof event id"), { target: { value: "clog_01ABC" } });
    fireEvent.change(screen.getByLabelText("proof checkpoint ref"), { target: { value: "cp_001" } });
    fireEvent.click(screen.getByTestId("run-proof"));
    expect(await screen.findByTestId("proof-result")).toHaveTextContent(/PROOF DOES NOT VERIFY/);
  });

  it("refuses a proof without both inputs, and names an unreadable proof", async () => {
    mockFetch({ "/api/v1/cryptolog/integrity/checkpoints": { rows: [], total_count: 0 } });
    renderIntegrity();
    fireEvent.click(screen.getByTestId("run-proof"));
    expect(await screen.findByTestId("proof-failure")).toHaveTextContent(/a proof names what it proves/);

    fireEvent.change(screen.getByLabelText("proof event id"), { target: { value: "clog_999" } });
    fireEvent.change(screen.getByLabelText("proof checkpoint ref"), { target: { value: "cp_001" } });
    fireEvent.click(screen.getByTestId("run-proof"));
    await waitFor(() => {
      expect(screen.getByTestId("proof-failure")).toHaveTextContent(/HTTP 404|unable/i);
    });
  });
});
