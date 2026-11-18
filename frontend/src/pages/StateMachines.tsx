/* State machines — the product's own state vocabulary, on screen.
 *
 * Every state the platform can be in, observed from code and never invented.
 * This page is the UX face of the canonical register (shared_models
 * /state_machines.json): the same classes drive every tone in the console, the
 * same transitions drive what code may do, and the invariants are the honesty
 * rules the product already lives by. Machines whose vocabulary is not yet
 * observed say so here instead of inventing states. */
import { useState } from "react";

import { Panel, PageHead, Tabs, Code, Kicker } from "../components/ui";
import { toneColor } from "../components/viz";
import {
  MACHINES,
  REGISTER_PRINCIPLES,
  STATE_CLASSES,
  machinesByDomain,
  stateTone,
  type Machine,
  type StateClass,
} from "../lib/stateMachines";

const DOMAIN_ORDER = [
  "session", "ui", "collection", "evidence", "findings", "payments",
  "platform", "governance", "estate", "certificates", "cryptolog",
  "performance", "posture", "twin",
];

const DOMAIN_TITLES: Record<string, string> = {
  session: "Session & reads",
  ui: "Console vocabulary",
  collection: "Collection & scans",
  evidence: "Evidence & honesty",
  findings: "Findings & remediation",
  payments: "Payments & keys",
  platform: "Platform operations",
  governance: "Governance & audit",
  estate: "Estate & migration",
  certificates: "Certificates",
  cryptolog: "CryptoLog",
  performance: "Performance",
  posture: "Posture & PQC",
  twin: "Twin & cascade",
};

function StateChip({ machineId, state }: { machineId: string; state: { id: string; class: StateClass; meaning: string } }) {
  return <Chip label={state.id} tone={stateTone(machineId, state.id)} hint={state.meaning || state.class} classLabel={state.class} />;
}

function Chip({ label, tone, hint, classLabel }: { label: string; tone: string; hint: string; classLabel: string }) {
  const color = toneColor(tone);
  return (
    <span
      title={hint}
      style={{
        display: "inline-flex", alignItems: "center", gap: 6,
        border: `1px solid ${color}`, borderRadius: 3,
        padding: "2px 8px", marginRight: 6, marginBottom: 6,
        fontFamily: "ui-monospace, monospace", fontSize: 12,
      }}
    >
      <span aria-hidden="true" style={{ width: 8, height: 8, borderRadius: 8, background: color, display: "inline-block" }} />
      <span>{label}</span>
      <span style={{ color: "var(--slate, #64748b)" }}>{classLabel}</span>
    </span>
  );
}

function MachinePanel({ machine }: { machine: Machine }) {
  return (
    <Panel
      title={machine.label}
      sub={`${machine.id} · ${machine.kind} · vocabulary ${machine.vocabulary}`}
    >
      {machine.description ? <p style={{ margin: "0 0 8px" }}>{machine.description}</p> : null}

      <Kicker>states</Kicker>
      {machine.states.length ? (
        <div style={{ margin: "4px 0 10px" }}>
          {machine.states.map((s) => (
            <StateChip key={s.id} machineId={machine.id} state={s} />
          ))}
        </div>
      ) : (
        <p style={{ margin: "4px 0 10px", color: "var(--slate, #64748b)" }}>
          <span title={"Vocabulary not yet observed — states are never guessed. The field exists and is listed so the register cannot rot around it."}>{"Vocabulary not yet observed"}</span>
        </p>
      )}

      <Kicker>transitions observed in code</Kicker>
      {machine.transitions.length ? (
        <div style={{ margin: "4px 0 10px" }}>
          {machine.transitions.map((t) => (
            <div key={`${t.from}->${t.to}`} style={{ display: "flex", gap: 8, alignItems: "baseline", marginBottom: 3, flexWrap: "wrap" }}>
              <Code>{t.from} → {t.to}</Code>
              <span style={{ fontSize: 12 }}>{t.trigger}</span>
            </div>
          ))}
        </div>
      ) : (
        <p style={{ margin: "4px 0 10px", color: "var(--slate, #64748b)" }}>
          <span title={"No edges observed in code — the vocabulary is pinned; edges appear only when code proves them."}>{"No edges observed in code"}</span>
        </p>
      )}

      {machine.invariants.length ? (
        <>
          <Kicker>invariants</Kicker>
          <ul style={{ margin: "4px 0 10px", paddingLeft: 18 }}>
            {machine.invariants.map((inv) => (
              <li key={inv} style={{ marginBottom: 3 }}>{inv}</li>
            ))}
          </ul>
        </>
      ) : null}

      {machine.fields.length ? (
        <>
          <Kicker>fields</Kicker>
          <div style={{ margin: "4px 0 0" }}>
            {machine.fields.map((f) => (
              <span key={f} style={{ marginRight: 8, display: "inline-block" }}><Code>{f}</Code></span>
            ))}
          </div>
        </>
      ) : null}
    </Panel>
  );
}

export default function StateMachines() {
  const byDomain = machinesByDomain();
  const domains = [
    ...DOMAIN_ORDER.filter((d) => byDomain.has(d)),
    ...[...byDomain.keys()].filter((d) => !DOMAIN_ORDER.includes(d)),
  ];
  const [tab, setTab] = useState(0);
  const activeDomain = domains[tab] ?? domains[0];
  const machines = byDomain.get(activeDomain) ?? [];

  return (
    <div>
      <PageHead
        crumb="Administration / State machines"
        title="State machines"
        sub="Every state the product can be in — observed from code, never invented. One vocabulary for UX, DX and agents: the console renders these tones, code may only make these moves, and the register is machine-readable."
      />

      <Panel title="How to read this register" sub="the rules the register enforces on itself">
        <ul style={{ margin: 0, paddingLeft: 18 }}>
          {REGISTER_PRINCIPLES.map((p) => (
            <li key={p} style={{ marginBottom: 4 }}>{p}</li>
          ))}
        </ul>
      </Panel>

      <Panel title="State classes" sub="one tone per semantic class — a state looks the same on every page">
        <div>
          {(Object.keys(STATE_CLASSES) as StateClass[]).map((cls) => (
            <Chip
              key={cls}
              label={cls}
              tone={STATE_CLASSES[cls].tone}
              hint={STATE_CLASSES[cls].meaning}
              classLabel={STATE_CLASSES[cls].tone}
            />
          ))}
        </div>
        <p style={{ margin: "8px 0 0", color: "var(--slate, #64748b)", fontSize: 12 }}>
          <span title={"Hover a chip for what the class means. An undeclared state always renders slate — an undeclared state must never render as a pass."}>{"Hover a chip for what the class means."}</span>
        </p>
      </Panel>

      <Tabs
        tabs={domains.map((d) => DOMAIN_TITLES[d] ?? d)}
        active={tab}
        onChange={setTab}
      />
      <div style={{ marginTop: 12 }}>
        <p style={{ margin: "0 0 10px", color: "var(--slate, #64748b)", fontSize: 12 }}>
          {machines.length} machine{machines.length === 1 ? "" : "s"} in this domain.
          {" "}Total: {MACHINES.length} machines across {domains.length} domains.
        </p>
        {machines.map((m) => (
          <MachinePanel key={m.id} machine={m} />
        ))}
      </div>
    </div>
  );
}
