/* Compact Operations read-model fixtures, shaped like /api/v1/operations/* answers. */
import type { OpsActivity, OpsAgent, OpsEvent, OpsFleet, OpsHost, OpsHosts, OpsMonitor } from "../lib/api";

export const NOW_ISO = new Date().toISOString();
const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();

export function agent(name: string, over: Partial<OpsAgent> & { age?: number | null; system?: OpsAgent["system"]; cpu?: number | null } = {}): OpsAgent {
  const { age = 20, cpu = 25, ...rest } = over;
  const state = age === null ? "NEVER_REPORTED" : age > 600 ? "OFFLINE" : age > 180 ? "LATE" : "LIVE";
  return {
    name, agent_id: `id-${name}`, registered: true, registry_status: "ACTIVE",
    liveness: { state, age_seconds: age, last_heartbeat_at: age === null ? null : ago(age), late_after_seconds: 180, offline_after_seconds: 600, meaning: "" },
    healthy: true, link: "direct", version: "1.4.0", target_version: null, buffered: 0, platform: "linux", environment: "sandbox",
    last_seen_ip: "10.210.0.4", enrolled_at: ago(3600),
    host: { name: name.split("-").pop() ?? name, fqdn: `${name}.mrdn.bank`, ip_addresses: ["10.210.0.4"], os: "Ubuntu 22.04", kernel: "5.15", architecture: "x86_64", fips_mode: false },
    system: { name: "SWIFT Gateway", criticality: "tier-0", owner: "Payments" },
    slice: { assets: 30, evidence: 40, relationships: 20, asset_types: {}, observed_at: ago(60), last_changed_at: ago(600), authenticity: "SIGNED", key_id: "ed25519:abc" },
    planes: [
      { plane: "Cryptographic (CBOM)", bom: "CBOM", status: "COMPLETE", reason: "every source read", source_states: { READ: 2 },
        sources: [{ source: "tls-config", reads: "/etc/nginx", state: "READ", found: 3 }, { source: "pkcs11", state: "NOT_CONFIGURED", note: "no HSM module path" }] },
      { plane: "Network (NBOM)", bom: "NBOM", status: "PARTIAL", reason: "one source unavailable", source_states: { READ: 1, ABSENT: 1 },
        sources: [{ source: "proc-net", state: "READ", found: 4 }] },
    ],
    plane_states: { COMPLETE: 1, PARTIAL: 1 }, source_states: { READ: 3, NOT_CONFIGURED: 1 },
    performance: cpu === null
      ? { state: "NOT_SAMPLED", sampled_at: null, age_seconds: null, latest: {}, series: {}, meaning: "no performance sample received" }
      : { state: "SAMPLED", sampled_at: ago(30), age_seconds: 30, latest: { cpu_pct: { value: cpu }, ram_pct: { value: 61 } },
          series: { cpu_pct: [[ago(90), cpu - 5], [ago(60), cpu + 3], [ago(30), cpu]] } },
    issues: [],
    ...rest,
  };
}

export function fleet(agents: OpsAgent[]): OpsFleet {
  const by: Record<string, number> = {};
  agents.forEach((a) => { by[a.liveness.state] = (by[a.liveness.state] ?? 0) + 1; });
  return {
    schema: "cryptoscan.operations-fleet/1", at: NOW_ISO, run_id: "run-1", heartbeat_seconds: 60,
    late_after_seconds: 180, offline_after_seconds: 600,
    totals: { agents: agents.length, by_liveness: by, live: by.LIVE ?? 0, reporting: (by.LIVE ?? 0) + (by.LATE ?? 0),
              with_issues: agents.filter((a) => a.issues.length).length, buffered: 0,
              plane_states: { COMPLETE: agents.length, PARTIAL: agents.length }, source_states: { READ: 3 * agents.length, NOT_CONFIGURED: agents.length },
              systems: [...new Set(agents.map((a) => a.system?.name).filter(Boolean) as string[])] },
    agents, limits: ["liveness is the heartbeat, not proof every collector ran"],
  };
}

export function host(a: OpsAgent, over: Partial<OpsHost> = {}): OpsHost {
  return {
    agent: a.name, host: a.host, system: a.system, liveness: a.liveness, performance: a.performance,
    services: [{ name: "nginx", executable: "/usr/sbin/nginx", user: "www-data", listens_on: "0.0.0.0:8443", running: true, libraries: ["OpenSSL 3.0.15"] }],
    listeners: [{ name: "l1", host: "0.0.0.0", port: "8443", protocol: "tcp", process: "nginx", loopback_only: false, tls_version: "TLSv1.3", cipher: null }],
    libraries: [{ name: "OpenSSL 3.0.15", version: "3.0.15", path: "/usr/lib/libssl.so.3", loaded: true, loaded_by: ["nginx"] }],
    certificates: [{ name: "gateway.mrdn.bank", subject: "CN=gateway", issuer: "CN=Meridian CA", algorithm: "RSA", key_size: 2048, not_after: null, days_left: 20 }],
    keys: [], algorithms: [{ algorithm: "RSA", verdict: "SHOR_VULNERABLE", status: "ACTIVE", runtime: true, assets: ["gateway.mrdn.bank"] }],
    evidence_types: {}, runtime_evidence: 11,
    counts: { services: 1, running_services: 1, listeners: 1, exposed_listeners: 1, libraries: 1, loaded_libraries: 1, quantum_vulnerable: 1 },
    ...over,
  };
}

export function hosts(list: OpsHost[]): OpsHosts {
  return {
    schema: "cryptoscan.operations-hosts/1", at: NOW_ISO, run_id: "run-1", hosts: list,
    totals: { hosts: list.length, sampled: list.length, running_services: list.length, loaded_libraries: list.length,
              quantum_vulnerable: list.length, runtime_evidence: 11 * list.length },
    thresholds: { cpu_pct: 85 }, limits: ["a library is loaded only when a running process maps it"],
  };
}

export function monitor(agents: OpsAgent[], over: Partial<OpsMonitor> = {}): OpsMonitor {
  const f = fleet(agents);
  return {
    schema: "cryptoscan.operations-monitor/1", at: NOW_ISO,
    status: { state: "OPERATIONAL", headline: "Every agent is reporting", meaning: "heartbeats inside the interval" },
    connection: { state: "LIVE", last_observation: ago(40), seconds_since: 40, interval_seconds: 300, stale_after_seconds: 600, meaning: "" },
    coverage: { coverage_percent: 84.2, expected: 133, collected: 112 },
    alerts: [], alert_counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
    fleet: { heartbeat_seconds: 60, late_after_seconds: 180, offline_after_seconds: 600, totals: f.totals, agents },
    changes: { total: 3, unacknowledged: 1, last_at: ago(300), last_headline: "Crypto changed" },
    twin: { run_id: "run-1-abcdef", recorded_at: ago(60), assets: 200, evidence: 300 },
    limits: ["a quiet screen means the agents report, not that the estate is safe"],
    ...over,
  };
}

export function event(id: string, over: Partial<OpsEvent> = {}): OpsEvent {
  return {
    id, kind: "agent", at: ago(120), severity: "INFO", title: "Agent activated", detail: null, next_action: null,
    agents: ["mrdn-sbx-dc1-swiftgw01"], systems: ["SWIFT Gateway"], acknowledged: null, ref: null, counts: {},
    items: [], item_total: 0, link: null, ...over,
  };
}

export function activity(events: OpsEvent[]): OpsActivity {
  const by_kind: Record<string, number> = {};
  const by_severity: Record<string, number> = {};
  events.forEach((e) => { by_kind[e.kind] = (by_kind[e.kind] ?? 0) + 1; by_severity[e.severity] = (by_severity[e.severity] ?? 0) + 1; });
  return {
    schema: "cryptoscan.operations-activity/1", at: NOW_ISO, window_hours: 24, events,
    totals: { events: events.length, last_24h: events.length, by_kind, by_severity,
              unacknowledged_changes: events.filter((e) => e.acknowledged === false).length },
    hourly: { from: ago(86400), to: NOW_ISO, counts: Array.from({ length: 24 }, (_, i) => (i === 23 ? events.length : 0)) },
    limits: [],
  };
}
