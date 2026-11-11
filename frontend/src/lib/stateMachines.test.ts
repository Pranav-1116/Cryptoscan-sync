/* Pins for the State Machine Register (TS projection).
 *
 * Cross-language parity (this JSON == the canonical one) is pinned in
 * shared/shared_models/tests/test_state_machines.py — byte equality. What is
 * pinned here is what the console depends on: shape, tones, honesty behaviour. */
import { describe, expect, it } from "vitest";

import {
  MACHINES,
  REGISTER_PRINCIPLES,
  STATE_CLASSES,
  canTransition,
  machine,
  machineForField,
  machinesByDomain,
  stateClass,
  stateTone,
  statesOf,
} from "./stateMachines";

describe("state machine register", () => {
  it("is the canonical vocabulary: every machine observed, sourced and classified", () => {
    expect(MACHINES.length).toBeGreaterThanOrEqual(90);
    for (const m of MACHINES) {
      expect(m.vocabulary_source.length > 0 || m.kind === "session" || m.kind === "ui").toBe(true);
      expect(["observed", "partial", "unobserved"]).toContain(m.vocabulary);
      for (const s of m.states) {
        expect(STATE_CLASSES[s.class as keyof typeof STATE_CLASSES]).toBeTruthy();
      }
    }
  });

  it("carries the honesty principles verbatim", () => {
    expect(REGISTER_PRINCIPLES.join(" ")).toMatch(/unknown is never zero/);
    expect(REGISTER_PRINCIPLES.join(" ")).toMatch(/Capability is never usage/);
    expect(REGISTER_PRINCIPLES.join(" ")).toMatch(/Nothing is invented/);
  });

  it("registers every machine the console draws states from", () => {
    for (const id of [
      "session.tenant_resolution", "session.read_health", "ui.flow_stage",
      "ui.performance_tile", "ui.tone", "collector.depth",
      "binary.usage_status", "os.rule_evaluation", "scan.status",
      "security_control.finding_state", "common.severity", "maturity.surface",
    ]) {
      expect(machine(id).id).toBe(id);
    }
  });

  it("tones follow the class — a state looks the same on every page", () => {
    expect(stateTone("scan.status", "FAILED")).toBe(STATE_CLASSES.failure.tone);
    expect(stateTone("scan.status", "COMPLETED")).toBe(STATE_CLASSES.done.tone);
    expect(stateTone("scan.status", "QUEUED")).toBe(STATE_CLASSES.progress.tone);
    expect(stateClass("scan.status", "CANCELLED")).toBe("stopped");
  });

  it("an undeclared state renders slate — never a pass", () => {
    expect(stateTone("scan.status", "NOT_A_STATE")).toBe("slate");
    expect(stateClass("scan.status", "NOT_A_STATE")).toBeNull();
    for (const m of MACHINES) {
      if (m.vocabulary === "unobserved") {
        expect(m.states).toEqual([]);
        expect(stateTone(m.id, "anything")).toBe("slate");
      }
    }
  });

  it("capability never gains an edge into usage", () => {
    expect(canTransition("binary.usage_status", "capability_only", "runtime_confirmed")).toBe(false);
    expect(canTransition("binary.usage_status", "statically_supported", "runtime_confirmed")).toBe(false);
    expect(canTransition("binary.usage_status", "capability_only", "statically_referenced")).toBe(true);
  });

  it("transitions are closed over declared states", () => {
    for (const m of MACHINES) {
      const declared = new Set(m.states.map((s) => s.id));
      for (const t of m.transitions) {
        expect(declared.has(t.from), `${m.id}: ${t.from}`).toBe(true);
        expect(declared.has(t.to), `${m.id}: ${t.to}`).toBe(true);
      }
    }
  });

  it("looks machines up by id, field and domain", () => {
    expect(machineForField("scan.Scan.status")?.id).toBe("scan.status");
    expect(machineForField("nope.Nope.status")).toBeUndefined();
    expect(statesOf("tenant.status")).toContain("ACTIVE");
    const domains = machinesByDomain();
    expect(domains.get("collection")?.length).toBeGreaterThan(0);
    expect(domains.get("session")?.length).toBeGreaterThanOrEqual(3);
    expect(() => machine("no.such.machine")).toThrow(/unknown state machine/);
  });
});
