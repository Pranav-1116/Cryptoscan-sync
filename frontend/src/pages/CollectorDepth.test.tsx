/* Collector depth: print the server's limits, never a rounded-up version of them. */
import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "../test/render";
import { mockFetch, offlineFetch } from "../test/setup";
import CollectorDepth from "./CollectorDepth";

const RUNTIME = "/api/v1/estate/evidence/discovery/runtime-depth";
const NETWORK = "/api/v1/estate/evidence/discovery/network-protocols";
const WINDOWS = "/api/v1/estate/evidence/discovery/windows-collector";
const BOMS = "/api/v1/estate/evidence/discovery/bom-maturity";
const MATURITY = "/api/v1/estate/evidence/discovery/maturity";
const SIMULATION = "/api/v1/estate/evidence/twin/simulation-scenarios";

const runtimeDoc = (overrides: Record<string, unknown> = {}) => ({
  schema: "cryptoscan.runtime-depth/1",
  paths: [
    {
      id: "openssl_native",
      label: "Native processes (OpenSSL)",
      family: "ELF / dynamically linked",
      depth: "INVOCATION",
      declared_depth: "INVOCATION",
      depth_meaning: "a cryptographic API call in a running process was observed and counted",
      producers: [{ ref: "runtime.agent.preload_trace:trace_command", present: true, reason: null }],
      producers_present: 1,
      ingest_only: ["OPENSSL_TRACE"],
      reads: "one record per EVP_* call under the shim",
      cannot_claim: "a statically linked binary or a Go binary with its own TLS stack produces NOTHING",
      gaps: ["no eBPF/uprobe capture, so long-running services cannot be observed without a restart"],
      notes: [],
    },
    {
      id: "jvm",
      label: "JVM applications",
      family: "Java virtual machine",
      depth: "INGEST_ONLY",
      declared_depth: "INGEST_ONLY",
      depth_meaning: "the platform can receive these observations, but no collector here produces them",
      producers: [],
      producers_present: 0,
      ingest_only: ["JVM_JCE"],
      reads: "nothing in this build",
      cannot_claim: "a JVM application's crypto is not observed by this platform today",
      gaps: ["no -javaagent collector"],
      notes: [],
    },
  ],
  depths: ["INVOCATION", "CONFIGURATION", "PROCESS_LIBRARY", "INGEST_ONLY", "ABSENT"],
  depth_meaning: {},
  rollup: { paths: 8, by_depth: {}, call_level_paths: 1, ingest_only_paths: 4, absent_paths: 1 },
  observed: {
    state: "NO_INVOCATION_EVIDENCE",
    reason: "the store holds only wire and library evidence — no process has been traced, so no algorithm invocation is known. This is not a statement that none ran",
    rows: 3,
    invocation_rows: 0,
    wire_rows: 3,
    library_risk_rows: 0,
    host_count: 1,
  },
  axiom: "OpenSSL installed is not AES-256 executed.",
  claim: "this lists what the platform can observe at runtime, per family, in this build",
  note: "ingest_only means the event contract accepts that source but no collector here produces it",
  ...overrides,
});

const networkDoc = (overrides: Record<string, unknown> = {}) => ({
  schema: "cryptoscan.network-protocols/1",
  protocols: [
    {
      id: "tls",
      label: "TLS / SSL",
      layer: "NETWORK_TRANSPORT",
      strength: "NEGOTIATED",
      declared_strength: "NEGOTIATED",
      strength_meaning: "a completed handshake",
      producers: [{ ref: "network_scanner.probing.tls_handshaker:handshake", present: true }],
      producers_present: 1,
      reads: "protocol version actually negotiated",
      cannot_claim: "a negotiated suite is what this connection agreed, not the application's own crypto",
      gaps: [],
      targets: ["NETWORK_ENDPOINT"],
      ingest_only: ["PASSIVE_PCAP"],
      notes: [],
    },
    {
      id: "ipsec",
      label: "IPsec / IKE",
      layer: "NETWORK_TRANSPORT",
      strength: "OFFERED",
      declared_strength: "OFFERED",
      strength_meaning: "what the peer offers before any session exists",
      producers: [{ ref: "network_scanner.probing.ipsec_probe:probe_ike", present: true }],
      producers_present: 1,
      reads: "SA proposals",
      cannot_claim: "a proposal set is not a tunnel",
      gaps: [],
      targets: ["NETWORK_ENDPOINT"],
      ingest_only: [],
      notes: [],
    },
    {
      id: "messaging",
      label: "Message brokers",
      layer: "APPLICATION",
      strength: "ABSENT",
      declared_strength: "ABSENT",
      strength_meaning: "no reader for this protocol in this build",
      producers: [],
      producers_present: 0,
      reads: "nothing",
      cannot_claim: "a broker on a TLS port is inferred from port and banner only",
      gaps: ["no Kafka SSL handshake read"],
      targets: ["MESSAGE_BROKER"],
      ingest_only: [],
      notes: [],
    },
  ],
  strengths: ["NEGOTIATED", "OFFERED", "SESSION_CONFIG", "PASSIVE", "ABSENT"],
  strength_meaning: {},
  rollup: { protocols: 11, by_strength: {}, negotiated: 3, offered_only: 2, absent: 3 },
  measured: { state: "NOT_OBSERVED", reason: "no estate discovery has run for this tenant", run_id: null },
  claim: "TLS is a completed-handshake reader",
  note: "an absent reader is listed as ABSENT rather than omitted",
  port_table: {
    ports: [
      { port: 5671, protocol: "amqp", label: "AMQP over TLS", classification: "IANA_REGISTERED", source: "IANA: amqps 5671/tcp", message_layer: "AMQP", plaintext_variant: false },
      { port: 5672, protocol: "amqp_plain", label: "AMQP plaintext", classification: "IANA_REGISTERED", source: "IANA: amqp 5672/tcp", message_layer: "AMQP", plaintext_variant: true },
    ],
    counts: { ports: 12, iana: 8, convention: 4 },
    claim: "a TLS handshake can be read on every port in this table",
  },
  ...overrides,
});

const windowsDoc = (overrides: Record<string, unknown> = {}) => ({
  schema: "cryptoscan.windows-collector/1",
  layers: [
    {
      id: "service_inventory",
      label: "Service and process inventory (SCM)",
      state: "PARTIAL",
      declared_state: "PARTIAL",
      state_meaning: "a collector exists but reads only part of what the layer holds",
      establishes: "SUBSTRATE",
      establishes_meaning: "the thing exists or runs — nothing about which crypto it used",
      producers: [{ ref: "inventory.windows_runtime:query_status", present: true }],
      producers_present: 1,
      reads: "the service control manager's view of a service",
      cannot_claim: "SCM tells us a service runs. It does not tell us what crypto that service performs",
      gaps: [],
      requires: "a Windows host the inventory agent can run on",
      notes: [],
    },
    {
      id: "schannel_events",
      label: "Schannel and CNG operation events (ETW)",
      state: "ABSENT",
      declared_state: "ABSENT",
      state_meaning: "nothing in this build reads this layer on Windows",
      establishes: "INVOCATION",
      establishes_meaning: "a cryptographic operation was observed happening",
      producers: [],
      producers_present: 0,
      reads: "nothing",
      cannot_claim: "this is the Windows invocation gap",
      gaps: ["no Microsoft-Windows-Schannel-Events consumer"],
      requires: "ETW session rights on the Windows host (not implemented)",
      notes: [],
    },
  ],
  states: ["PRESENT", "PARTIAL", "ABSENT"],
  state_meaning: {},
  evidence_classes: {},
  rollup: { layers: 11, by_state: { PRESENT: 0, PARTIAL: 7, ABSENT: 4 }, by_evidence: {}, invocation_layers: 0, substrate_layers: 4 },
  measured: { state: "NOT_OBSERVED", reason: "no estate discovery has run", run_id: null },
  verdict: {
    complete_collector: false,
    answer: "NO",
    reason: "every layer this build reaches on Windows reads substrate or configuration",
  },
  claim: "a Windows substrate collector",
  note: "the candidates run on the Windows host through the inventory agent",
  ...overrides,
});

const bomDoc = (overrides: Record<string, unknown> = {}) => ({
  schema: "cryptoscan.bom-maturity/1",
  estate: "payments-bank",
  projection_id: "abc123",
  boms: [
    {
      kind: "CBOM",
      label: "Cryptography BOM",
      question: "what cryptographic algorithms exist?",
      consumes: "every crypto artefact on every plane",
      ceiling: "OBSERVED",
      ceiling_meaning: "",
      cannot_claim: "a CBOM can reach runtime evidence — where a runtime collector runs",
      components: 12,
      relationships: 4,
      evidence_ids: 9,
      by_component_depth: { OBSERVED: 5, DECLARED_ONLY: 7 },
      observed_components: 5,
      configured_components: 0,
      declared_components: 7,
      unbacked_components: 0,
      depth: "OBSERVED",
      depth_meaning: "",
      at_ceiling: true,
    },
    {
      kind: "VBOM",
      label: "Vendor BOM",
      question: "what do the vendors say their products support?",
      consumes: "VENDOR assets",
      ceiling: "DECLARED_ONLY",
      ceiling_meaning: "",
      cannot_claim: "a declaration is not a fact about this estate",
      components: 3,
      relationships: 0,
      evidence_ids: 3,
      by_component_depth: { DECLARED_ONLY: 3 },
      observed_components: 0,
      configured_components: 0,
      declared_components: 3,
      unbacked_components: 0,
      depth: "DECLARED_ONLY",
      depth_meaning: "",
      at_ceiling: true,
    },
  ],
  depths: ["OBSERVED", "CONFIGURED", "DECLARED_ONLY", "UNBACKED", "EMPTY"],
  depth_meaning: {},
  rollup: { boms: 6, by_depth: {}, observed: 1, at_ceiling: 2 },
  deepest: ["CBOM"],
  shallowest: ["VBOM"],
  claim: "all six BOMs are projections of one evidence graph; they are not equally deep",
  note: "depth is the strongest evidence class behind a BOM's components",
  ...overrides,
});

describe("collector depth", () => {
  it("shows which runtime families reach call level and which are ingest-only", async () => {
    mockFetch({ [RUNTIME]: runtimeDoc(), [NETWORK]: networkDoc(), [WINDOWS]: windowsDoc(), [BOMS]: bomDoc() });
    renderWithProviders(<CollectorDepth />);

    const native = await screen.findByTestId("runtime-path-openssl_native");
    expect(native.textContent).toContain("INVOCATION");
    const jvm = screen.getByTestId("runtime-path-jvm");
    expect(jvm.textContent).toContain("INGEST ONLY");
    expect(jvm.textContent).toContain("JVM_JCE");
    // the axiom and the store's honest state are printed, not summarised away
    expect(screen.getByText(/installed is not AES-256 executed/i)).toBeTruthy();
    expect(screen.getByText(/This is not a statement that none ran/)).toBeTruthy();
  });

  it("prints per-protocol strength and lists the protocols with no reader", async () => {
    mockFetch({ [RUNTIME]: runtimeDoc(), [NETWORK]: networkDoc(), [WINDOWS]: windowsDoc(), [BOMS]: bomDoc() });
    renderWithProviders(<CollectorDepth />);
    await userEvent.click(screen.getByRole("button", { name: "Network" }));

    expect((await screen.findByTestId("protocol-tls")).textContent).toContain("NEGOTIATED");
    expect(screen.getByTestId("protocol-ipsec").textContent).toContain("OFFERED");
    const messaging = screen.getByTestId("protocol-messaging");
    expect(messaging.textContent).toContain("ABSENT");
    expect(messaging.textContent).toContain("inferred from port and banner only");
    // the estate-backed half is explicitly unread
    expect(screen.getByTestId("network-measured").textContent).toContain("no estate discovery has run");
    // the crypto-bearing port table is shown with its provenance split
    const table = screen.getByTestId("port-table");
    expect(table.textContent).toContain("12 ports");
    expect(table.textContent).toContain("8 IANA-registered");
    expect(table.textContent).toContain("4 vendor convention");
  });

  it("answers the Windows question with the server's NO", async () => {
    mockFetch({ [RUNTIME]: runtimeDoc(), [NETWORK]: networkDoc(), [WINDOWS]: windowsDoc(), [BOMS]: bomDoc() });
    renderWithProviders(<CollectorDepth />);
    await userEvent.click(screen.getByRole("button", { name: "Windows" }));

    const verdict = await screen.findByTestId("windows-verdict");
    expect(verdict.textContent).toContain("NO");
    expect(verdict.textContent).toContain("0 of 11 layers observe an operation");
    // the SCM candidate says what it is, not what it is not
    expect(screen.getByTestId("windows-layer-service_inventory").textContent).toContain("establishes substrate");
    expect(screen.getByTestId("windows-layer-schannel_events").textContent).toContain("the Windows invocation gap");
  });

  it("prints the register's states and its missing work, not a score", async () => {
    mockFetch({
      [RUNTIME]: runtimeDoc(),
      [NETWORK]: networkDoc(),
      [WINDOWS]: windowsDoc(),
      [BOMS]: bomDoc(),
      [MATURITY]: {
        schema: "cryptoscan.maturity-register/1",
        areas: [
          {
            id: "NETWORK_DISCOVERY",
            label: "Network discovery",
            state: "PARTIAL",
            readiness: "CANDIDATE",
            readiness_meaning: "code exercises real inputs but is not admitted as a production capability",
            summary: "TLS is a handshake reader; MQ has no reader at all.",
            surfaces: [
              {
                id: "TLS",
                label: "TLS",
                state: "SUBSTANTIAL",
                state_meaning: "a collector reads this surface from a source of truth",
                collector: "services/network_scanner/",
                note: "completed-handshake reader",
                missing: [],
              },
              {
                id: "MQ",
                label: "Message queues",
                state: "ABSENT",
                state_meaning: "nothing reads this surface",
                collector: null,
                note: "no reader exists in this build",
                missing: ["AMQP/MQTT/Kafka readers"],
              },
            ],
            missing: ["message-queue readers", "passive traffic coverage"],
            measured_by: ["/estate/evidence/discovery/network-protocols"],
            claim: "Each protocol is reported with the reader that exists, or as absent.",
            must_not_be_presented_as: ["Complete network crypto coverage across an enterprise."],
          },
        ],
        boundaries: [
          {
            id: "HSM_OPERATIONS",
            area: "HARDWARE_HSM",
            capability: "HSM",
            status: "FOUNDATION",
            says: "The HSM model is metadata. It is not proof of actual HSM cryptographic operations.",
            not_operational: "proof that a key operation ran inside an HSM",
            what_is_real: "a PKCS#11 seam for signing and certificate relationships",
            check_at: "/estate/evidence/discovery/maturity",
          },
        ],
        claims: {
          may_claim: "an evidence-driven framework across surfaces, stating where coverage stops",
          may_not_claim: ["CryptoScan discovers every cryptographic asset in any bank environment."],
          why: "a completeness claim over an estate the product has not seen",
        },
      },
    });
    renderWithProviders(<CollectorDepth />);
    await userEvent.click(screen.getByRole("button", { name: "Maturity" }));

    const tls = await screen.findByTestId("surface-TLS");
    expect(tls.textContent).toContain("SUBSTANTIAL");
    expect(tls.textContent).toContain("services/network_scanner/");

    const mq = screen.getByTestId("surface-MQ");
    expect(mq.textContent).toContain("ABSENT");
    expect(mq.textContent).toContain("no collector in this build");
    expect(mq.textContent).toContain("AMQP/MQTT/Kafka readers");

    expect(screen.getByText(/every cryptographic asset in any bank environment/i)).toBeTruthy();
    expect(screen.getByText(/message-queue readers/i)).toBeTruthy();

    // what may be said about the area, printed next to what it covers
    expect(screen.getByTestId("readiness-NETWORK_DISCOVERY").textContent).toBe("CANDIDATE");

    // the boundaries are met before the coverage numbers, and they are not softened
    const hsm = screen.getByTestId("boundary-HSM_OPERATIONS");
    expect(screen.getByTestId("boundary-status-HSM_OPERATIONS").textContent).toBe("FOUNDATION");
    expect(hsm.textContent).toContain("not proof of actual HSM cryptographic operations");
    expect(hsm.textContent).toContain("proof that a key operation ran inside an HSM");
    expect(hsm.textContent).toContain("/estate/evidence/discovery/maturity");
    const mayNot = screen.getByTestId("maynot-NETWORK_DISCOVERY");
    expect(mayNot.textContent).toContain("must not be presented as");
    expect(mayNot.textContent).toContain("Complete network crypto coverage across an enterprise.");
  });

  it("says the simulation engine is scenario-specific, not generic", async () => {
    mockFetch({
      [RUNTIME]: runtimeDoc(),
      [NETWORK]: networkDoc(),
      [WINDOWS]: windowsDoc(),
      [BOMS]: bomDoc(),
      [SIMULATION]: {
        schema: "cryptoscan.enterprise-simulation-scenarios/1",
        statuses: {},
        scenarios: [
          {
            id: "PQC_MIGRATION",
            label: "PQC migration",
            status: "EXISTS",
            status_meaning: "a scenario computes this today over collected evidence",
            covered_by: [{ engine: "agility", scenario: "pqc_migration", present: true }],
            cannot: [],
            requires: [],
            note: "",
          },
          {
            id: "TRUST_COMPROMISE",
            label: "Trust compromise",
            status: "ABSENT",
            status_meaning: "nothing computes this",
            covered_by: [],
            cannot: ["no CA hierarchy is modelled, so a compromised intermediate CA cannot be traced"],
            requires: ["a PKI hierarchy model"],
            note: "",
          },
        ],
        rollup: { scenarios: 10, EXISTS: 1, PARTIAL: 7, ABSENT: 2 },
        unresolved: [],
        cannot_claim: ["A generic enterprise simulation engine that answers arbitrary what-if questions across every crypto failure mode."],
        note: "PARTIAL and ABSENT are the boundary of an evidence-driven engine.",
      },
    });
    renderWithProviders(<CollectorDepth />);
    await userEvent.click(screen.getByRole("button", { name: "Simulation" }));

    const pqc = await screen.findByTestId("simulation-PQC_MIGRATION");
    expect(pqc.textContent).toBe("EXISTS");
    expect(screen.getByText("agility/pqc_migration")).toBeTruthy();

    const trust = screen.getByTestId("simulation-TRUST_COMPROMISE");
    expect(trust.textContent).toBe("ABSENT");
    // an absent scenario names its gap and its missing dependency — it is not softened
    expect(screen.getByText(/compromised intermediate CA cannot be traced/)).toBeTruthy();
    expect(screen.getByText(/a PKI hierarchy model/)).toBeTruthy();
    expect(screen.getByText(/generic enterprise simulation engine/i)).toBeTruthy();
    expect(screen.getByText(/1 computed · 7 partial · 2 absent/)).toBeTruthy();
  });

  it("reports BOM depth against each BOM's own ceiling", async () => {
    mockFetch({ [RUNTIME]: runtimeDoc(), [NETWORK]: networkDoc(), [WINDOWS]: windowsDoc(), [BOMS]: bomDoc() });
    renderWithProviders(<CollectorDepth />);
    await userEvent.click(screen.getByRole("button", { name: "Six BOMs" }));

    const cbom = await screen.findByTestId("bom-CBOM");
    expect(cbom.textContent).toContain("OBSERVED");
    expect(cbom.textContent).toContain("ceiling OBSERVED");
    const vbom = screen.getByTestId("bom-VBOM");
    expect(vbom.textContent).toContain("DECLARED ONLY");
    expect(vbom.textContent).toContain("a declaration is not a fact about this estate");
  });

  it("claims nothing about BOM depth without a stored snapshot", async () => {
    mockFetch({
      [RUNTIME]: runtimeDoc(),
      [NETWORK]: networkDoc(),
      [WINDOWS]: windowsDoc(),
      [BOMS]: {
        schema: "cryptoscan.bom-maturity/1",
        state: "NOT_OBSERVED",
        reason: "no estate discovery has run for this tenant",
        boms: [],
        claim: "with no snapshot there is nothing to project",
      },
    });
    renderWithProviders(<CollectorDepth />);
    await userEvent.click(screen.getByRole("button", { name: "Six BOMs" }));

    const unobserved = await screen.findByTestId("bom-unobserved");
    expect(unobserved.textContent).toContain("no estate discovery has run");
    expect(screen.queryByTestId("bom-CBOM")).toBeNull();
  });

  it("opens a BOM's component list with the server's own usage states", async () => {
    mockFetch({
      [RUNTIME]: runtimeDoc(),
      [NETWORK]: networkDoc(),
      [WINDOWS]: windowsDoc(),
      [BOMS]: bomDoc(),
      "/api/v1/estate/evidence/boms": {
        schema: "cryptoscan.estate-boms/1",
        bom: "CBOM",
        question: "what cryptographic algorithms exist?",
        estate: "payments-bank",
        run_id: "run-1",
        projection_id: "abc123def456",
        components: [
          {
            bom_ref: "crypto://1",
            artifact_id: "crypto-1",
            algorithm: "AES-256-GCM",
            role: "record_protection",
            type: "CRYPTO_ARTIFACT",
            usage_state: "NEGOTIATED",
            evidence_type: "NETWORK_ACTIVE_OBSERVED",
            evidence_ids: ["ev-1"],
            asset_name: "payments-bank-app-0",
          },
          {
            bom_ref: "crypto://2",
            artifact_id: "crypto-2",
            algorithm: "SHA-256",
            role: "capability",
            type: "CRYPTO_ARTIFACT",
            usage_state: "SUPPORTED",
            evidence_type: "VENDOR_DECLARED",
            evidence_ids: [],
            asset_name: "payments-bank-app-1",
          },
        ],
      },
    });
    renderWithProviders(<CollectorDepth />);
    await userEvent.click(screen.getByRole("button", { name: "Six BOMs" }));
    await screen.findByTestId("bom-CBOM");

    await userEvent.click(screen.getByRole("button", { name: "Show CBOM components" }));

    const table = await screen.findByText("AES-256-GCM");
    expect(table).toBeTruthy();
    expect(screen.getByText("SHA-256")).toBeTruthy();
    // the state is printed as the server reported it, and the split is counted, not guessed
    expect(screen.getAllByText("NEGOTIATED").length).toBeGreaterThan(0);
    expect(screen.getByText(/All 2 components shown/)).toBeTruthy();
    expect(screen.getByText(/estate payments-bank/)).toBeTruthy();
  });

  it("prints an empty BOM as empty rather than as an absence of crypto", async () => {
    mockFetch({
      [RUNTIME]: runtimeDoc(),
      [NETWORK]: networkDoc(),
      [WINDOWS]: windowsDoc(),
      [BOMS]: bomDoc(),
      "/api/v1/estate/evidence/boms": {
        schema: "cryptoscan.estate-boms/1",
        bom: "VBOM",
        question: "what do the vendors say?",
        estate: "payments-bank",
        run_id: "run-1",
        components: [],
      },
    });
    renderWithProviders(<CollectorDepth />);
    await userEvent.click(screen.getByRole("button", { name: "Six BOMs" }));
    await screen.findByTestId("bom-VBOM");

    await userEvent.click(screen.getByRole("button", { name: "Show VBOM components" }));

    const empty = await screen.findByTestId("bom-components-empty-VBOM");
    expect(empty.textContent).toContain("no components in the stored observation");
    expect(empty.textContent).toContain("payments-bank");
  });

  it("says a matrix was not read instead of drawing it empty", async () => {
    offlineFetch();
    renderWithProviders(<CollectorDepth />);

    expect(await screen.findByText(/Runtime depth not read/)).toBeTruthy();
    expect(screen.queryByTestId("runtime-path-openssl_native")).toBeNull();
  });
});
