/* The canonical State Machine Register — TypeScript projection.
 *
 * The canonical JSON lives beside the Python projection at
 * shared/shared_models/shared_models/state_machines.json; the copy imported
 * here (stateMachines.json) is generated with it and must stay byte-identical
 * (shared_models/tests/test_state_machines.py fails when they drift).
 *
 * One vocabulary for every state in the product, observed from code and never
 * invented. unknown is never zero; a failed read is a failure; absence is never
 * a clean result; capability is never usage; a refusal is counted, never drawn
 * as a truth. State classes carry those semantics, and every state renders with
 * its class's tone — so the same state looks the same on every page. */
import REGISTER from "./stateMachines.json";

export type StateClass =
  | "progress" | "done" | "failure" | "stopped" | "warn"
  | "unknown" | "refused" | "absent" | "derived" | "capability" | "stale";

export interface MachineState {
  id: string;
  class: StateClass;
  meaning: string;
}

export interface MachineTransition {
  from: string;
  to: string;
  trigger: string;
  observed_in: string[];
}

export interface Machine {
  id: string;
  label: string;
  domain: string;
  kind: "lifecycle" | "verdict" | "vocabulary" | "session" | "ui";
  description: string;
  fields: string[];
  vocabulary: "observed" | "partial" | "unobserved";
  vocabulary_source: string;
  states: MachineState[];
  transitions: MachineTransition[];
  invariants: string[];
  sources: string[];
}

interface RegisterFile {
  schema_version: number;
  register: string;
  title: string;
  principles: string[];
  state_classes: Record<StateClass, { tone: string; meaning: string }>;
  machines: Machine[];
}

const REG = REGISTER as unknown as RegisterFile;

export const REGISTER_TITLE = REG.title;
export const REGISTER_PRINCIPLES = REG.principles;
export const STATE_CLASSES = REG.state_classes;
export const MACHINES: Machine[] = REG.machines;

const BY_ID = new Map<string, Machine>(MACHINES.map((m) => [m.id, m]));

export function machine(id: string): Machine {
  const m = BY_ID.get(id);
  if (!m) throw new Error(`unknown state machine ${id}`);
  return m;
}

export function statesOf(id: string): string[] {
  return machine(id).states.map((s) => s.id);
}

export function stateClass(machineId: string, stateId: string): StateClass | null {
  return machine(machineId).states.find((s) => s.id === stateId)?.class ?? null;
}

/** The viz tone word for one state. An undeclared state renders slate — an
 *  undeclared state must never render as a pass. */
export function stateTone(machineId: string, stateId: string): string {
  const cls = stateClass(machineId, stateId);
  return cls ? STATE_CLASSES[cls].tone : "slate";
}

/** Only transitions observed in code. States with no observed edges stay put
 *  by exhaustion, not by an implicit self-loop. */
export function canTransition(machineId: string, from: string, to: string): boolean {
  return machine(machineId).transitions.some((t) => t.from === from && t.to === to);
}

export function machinesByDomain(): Map<string, Machine[]> {
  const out = new Map<string, Machine[]>();
  for (const m of MACHINES) {
    const list = out.get(m.domain) ?? [];
    list.push(m);
    out.set(m.domain, list);
  }
  return out;
}

/** The machine that owns a model field ("scan.Scan.status"), or undefined. */
export function machineForField(fieldPath: string): Machine | undefined {
  return MACHINES.find((m) => m.fields.includes(fieldPath));
}
