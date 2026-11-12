import React, { useEffect, useState } from "react";
import { Badge, Panel } from "../components/ui.jsx";
import { FlowStrip, StepRail } from "../components/viz";
import {
  apiCryptologEvents, type ApiResult, type CryptologEventRow,
} from "../lib/api.js";

/* Workspace 1 — Crypto Event Stream (docs/cryptolog/01_PRODUCT_SPEC.md §3
   and the eight-workspace design). The landing workspace opens with HOW
   CryptoLog works — the pipeline is the product, not a footer diagram —
   then the illustrative detection example, then the product data flow, and
   finally the chronological stream of recorded events. The stream counts
   what the store returned: "X loaded", never an invented total, and an
   empty stream is absence of recorded events, never a quiet estate. */

const PIPELINE = [
  { label: "Authorized event sources", state: "active" as const,
    note: "Applications · TLS · Certificates · HSM/KMS · OS/Kernel · Cloud · Network · crypto libraries — read-only and authorized only" },
  { label: "Event collectors", state: "active" as const,
    note: "Read-only adapters · approved APIs · native events · metrics · scheduled observations" },
  { label: "Normalization", state: "active" as const,
    note: "Canonical schema · timestamp normalization · asset identity · deduplication · event classification" },
  { label: "Evidence reference", state: "active" as const,
    note: "Source · digest · provenance · confidence" },
  { label: "Integrity engine", state: "active" as const,
    note: "Hash chain · signatures · checkpoints" },
  { label: "CryptoLog intelligence", state: "active" as const,
    note: "Event correlation · rules · change detection · historical timeline" },
];

const CONSUMERS = [
  { label: "Digital Twin", state: "unknown" as const,
    note: "Asset state and history — read from shared registers; an automatic feed is not claimed in this build" },
  { label: "Risk & PQC", state: "unknown" as const,
    note: "Exposure and migration signals — read from shared registers; an automatic feed is not claimed in this build" },
  { label: "Governance", state: "unknown" as const,
    note: "Audit and compliance — reached by export and shared registers; an automatic feed is not claimed in this build" },
  { label: "Command Center", state: "unknown" as const,
    note: "Operational alerts — reached by export and shared registers; an automatic feed is not claimed in this build" },
];

const EXAMPLE_STEPS = [
  { n: 1, title: "Observed", note: "10:00 — Payment API certificate observed: fingerprint, issuer, expiry and source recorded" },
  { n: 2, title: "Change detected", note: "10:30 — an authorized collector detects that the TLS configuration has changed" },
  { n: 3, title: "Event recorded", note: "10:31 — the event receives an ID, asset reference, timestamp, source and evidence reference" },
  { n: 4, title: "Integrity verification", note: "10:32 — the event digest is calculated and linked to the previous ledger entry; a signature or checkpoint can add verification" },
  { n: 5, title: "Correlation", note: "10:33 — the event is compared with previous observations and applicable deterministic rules" },
  { n: 6, title: "Digital Twin update", note: "10:34 — the Twin receives the observation and updates the asset's time-aware state, preserving the previous state" },
  { n: 7, title: "Risk assessment", note: "10:35 — if the change introduces a weak configuration, the risk engine creates a finding with supporting evidence" },
  { n: 8, title: "Verification", note: "later — after an approved change, a fresh observation verifies whether the intended configuration is present" },
];

const PRODUCT_FLOW = [
  { n: 1, title: "Discovery", note: "collects authorized HSM metadata and application evidence" },
  { n: 2, title: "Evidence Processing", note: "stores the observations and provenance" },
  { n: 3, title: "HBOM", note: "records the hardware and firmware information" },
  { n: 4, title: "CBOM", note: "records the supported cryptographic assets and observed crypto usage" },
  { n: 5, title: "SBOM", note: "records the software dependencies" },
  { n: 6, title: "TechBOM", note: "provides the wider technology inventory" },
  { n: 7, title: "Digital Twin", note: "connects the application and HSM only if evidence or an approved mapping establishes that relationship" },
  { n: 8, title: "CryptoLog", note: "records the cryptographic events and their integrity" },
  { n: 9, title: "PQC Intelligence", note: "evaluates relevant algorithm exposure and migration constraints" },
  { n: 10, title: "Simulation", note: "estimates the impact of a proposed HSM or algorithm change" },
  { n: 11, title: "Remediation", note: "tracks the approved work" },
  { n: 12, title: "Rescanning", note: "verifies the resulting state" },
];

function observedAt(event: CryptologEventRow): string {
  const observation = event.observation as Record<string, unknown>;
  return String(observation?.observed_at ?? "") || "unknown time";
}

export default function CryptoLogStream() {
  const [events, setEvents] = useState<CryptologEventRow[]>([]);
  const [failure, setFailure] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(0);

  useEffect(() => {
    apiCryptologEvents({ limit: 25 }).then((result: ApiResult<{ events: CryptologEventRow[]; returned: number }>) => {
      if (!result.data) {
        setFailure(result.error ?? "the event stream did not load");
        return;
      }
      setEvents(result.data.events);
      setLoaded(result.data.returned);
    });
  }, []);

  const sorted = [...events].sort((a, b) =>
    String(observedAt(b)).localeCompare(String(observedAt(a))));

  return (
    <div data-testid="cryptolog-stream">
      <Panel title="How CryptoLog works" sub="collect and normalize relevant cryptographic observations — never arbitrary system logs">
        <FlowStrip label="CryptoLog event intelligence pipeline" stages={PIPELINE} />
        <div className="dim" style={{ fontSize: 12, marginTop: 8 }}>
          Normalization is the contract: a canonical schema, one asset identity and
          an evidence reference (source, digest, provenance, confidence) on every
          record. The integrity engine then binds records into a hash chain with
          signed checkpoints — see Integrity Verification.
        </div>
        <div style={{ marginTop: 14 }}>
          <FlowStrip label="What consumes CryptoLog output" stages={CONSUMERS} />
        </div>
      </Panel>

      <Panel title="Illustrative example — how CryptoLog detects a cryptographic change" sub="a bank payment application using an RSA certificate">
        <div
          data-testid="stream-illustrative-label"
          style={{
            border: "1px dashed var(--rule)", borderRadius: 8, padding: "8px 12px",
            marginBottom: 12, background: "var(--panel-2)", fontSize: 12,
          }}
        >
          <strong>Illustrative timeline, not a claim about an existing CryptoScan
          live event feed.</strong>{" "}
          <span className="dim">The steps describe how the pipeline works; they are
          synthetic, never events from any deployment.</span>
        </div>
        <StepRail label="Example detection sequence (illustrative)" steps={EXAMPLE_STEPS} />
      </Panel>

      <Panel title="How the data moves between pages" sub="an HSM connected to a payment application — the product as one connected workflow">
        <StepRail label="Product data flow" steps={PRODUCT_FLOW} />
      </Panel>

      <Panel title="Crypto Event Stream" sub="a chronological stream of recorded cryptographic events — certificate changes, TLS configuration changes, HSM status changes, algorithm and crypto-provider changes">
        {failure ? (
          <div className="dim" data-testid="stream-failure">
            {failure} A source that could not be read is not a source with no events.
          </div>
        ) : sorted.length === 0 ? (
          <div
            data-testid="stream-empty"
            style={{
              display: "flex", gap: 10, alignItems: "flex-start",
              border: "1px dashed var(--rule)", borderRadius: 8, padding: "12px 14px",
              background: "var(--panel-2)",
            }}
          >
            <span
              aria-hidden
              style={{ width: 8, height: 8, borderRadius: 99, border: "1.5px dashed var(--slate, #64748b)", marginTop: 4, flex: "0 0 auto" }}
            />
            <div className="dim" style={{ fontSize: 12, lineHeight: 1.5 }}>
              No events recorded. An empty stream is absence of recorded events —
              never a quiet estate — and this stream never invents events.
            </div>
          </div>
        ) : (
          <>
            <div className="dim" data-testid="stream-loaded" style={{ fontSize: 12, marginBottom: 8 }}>
              {loaded} loaded · newest first among the loaded events · the store may hold more
            </div>
            <div data-testid="stream-rows" style={{ display: "grid", gap: 6 }}>
              {sorted.map((event) => (
                <div key={event.event_id} style={{
                  border: "1px solid var(--rule)", borderRadius: 6, padding: "8px 10px",
                  display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap",
                }}>
                  <span className="mono" data-testid="stream-row-time" style={{ fontSize: 11, color: "var(--faint)", minWidth: 150 }}>
                    {observedAt(event)}
                  </span>
                  <Badge tone={event.severity === "HIGH" || event.severity === "CRITICAL" ? "red"
                    : event.severity === "MEDIUM" ? "amber" : "slate"}>
                    {event.severity}
                  </Badge>
                  <span className="mono" style={{ fontSize: 12 }}>{event.event_type}</span>
                  <span className="dim" style={{ fontSize: 12 }}>{event.asset_id}</span>
                  <span className="dim" style={{ fontSize: 11, marginLeft: "auto" }}>
                    {event.investigation_status}
                  </span>
                </div>
              ))}
            </div>
          </>
        )}
      </Panel>
    </div>
  );
}
