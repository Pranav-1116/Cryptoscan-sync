/* Runtime hosts — every bank server an agent observed, live.
 *
 * Read from /api/v1/operations/hosts: per host, what runs on it (services, listening sockets,
 * the crypto libraries running processes have loaded, from /proc/<pid>/maps), the certificates,
 * keys and algorithms found on it with their quantum verdict, and its signed performance
 * samples (CPU, memory, load, connections). A host with no sample is NOT_SAMPLED, never idle.
 * The runtime crypto sensors (eBPF / adapters) sit below, collapsed. */
import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { apiOpsHosts, type OpsHost, type OpsHosts } from "../lib/api.js";
import { IconHardware } from "../components/icons";
import RuntimeSensors from "../components/RuntimeSensors";
import {
  Disclosure, KpiTile, LiveBar, LivenessPill, MiniSpark, OpsHeader, OpsLoadStates, card, fmtAge, inputStyle, kicker,
  metricValue, pctColor, useLive,
} from "../components/opsUi";

const VERDICT_COLOR: Record<string, string> = {
  SHOR_VULNERABLE: "var(--red)", GROVER_MARGINAL: "var(--amber)", QUANTUM_RESISTANT: "var(--green)",
  PQC_RESISTANT: "var(--green)", UNKNOWN: "var(--faint)",
};
const VERDICT_LABEL: Record<string, string> = {
  SHOR_VULNERABLE: "quantum-vulnerable", GROVER_MARGINAL: "weakened", QUANTUM_RESISTANT: "resistant",
  PQC_RESISTANT: "post-quantum", UNKNOWN: "unknown",
};

function Gauge({ label, value, unit = "%", warn = 75, crit = 90, series, max = 100 }: {
  label: string; value: number | null; unit?: string; warn?: number; crit?: number; series?: number[]; max?: number;
}) {
  const color = unit === "%" ? pctColor(value, warn, crit) : "var(--cyan)";
  return (
    <div aria-label={`${label} ${value === null ? "not sampled" : `${value}${unit}`}`} style={{ padding: 10, borderRadius: "var(--r)", background: "var(--panel-2)", border: "1px solid var(--line)", minWidth: 0 }}>
      <div style={kicker}>{label}</div>
      <div style={{ fontSize: 20, fontWeight: 800, color: value === null ? "var(--faint)" : color, fontVariantNumeric: "tabular-nums" }}>
        {value === null ? "—" : `${unit === "%" ? value.toFixed(0) : value}${unit}`}
      </div>
      {series ? <MiniSpark points={series} max={unit === "%" ? max : undefined} color={color} label={label} width={150} height={26} /> : null}
    </div>
  );
}

function HostDetail({ host }: { host: OpsHost }) {
  const p = host.performance;
  const series = (k: string) => (p.series?.[k] ?? []).map((x) => x[1]);
  return (
    <section aria-label={`Host ${host.host.name ?? host.agent}`} style={{ ...card, flex: "2 1 560px", minWidth: 320 }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
        <div>
          <div style={{ fontSize: 17, fontWeight: 800 }}>{host.host.fqdn ?? host.host.name ?? host.agent}</div>
          <div style={{ fontSize: 12, color: "var(--dim)" }}>
            {host.system?.name ?? "no system declared"}{host.system?.criticality ? ` · ${host.system.criticality}` : ""} · {host.host.ip_addresses.join(", ")}
          </div>
          <div style={{ fontSize: 11.5, color: "var(--faint)", marginTop: 2 }}>
            {[host.host.os, host.host.kernel, host.host.architecture].filter(Boolean).join(" · ")}
            {host.host.fips_mode === false ? " · FIPS mode off" : host.host.fips_mode ? " · FIPS mode on" : ""}
          </div>
        </div>
        <div style={{ textAlign: "right" }}>
          <LivenessPill state={host.liveness.state} age={host.liveness.age_seconds} />
          <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 4 }}>
            {p.state === "NOT_SAMPLED" ? "no performance sample" : `sample ${fmtAge(p.age_seconds)} ago`}
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 8, margin: "14px 0" }}>
        <Gauge label="CPU" value={metricValue(p.latest, "cpu_pct")} series={series("cpu_pct")} />
        <Gauge label="Memory" value={metricValue(p.latest, "ram_pct")} series={series("ram_pct")} />
        <Gauge label="Disk" value={metricValue(p.latest, "disk_pct")} />
        <Gauge label="Load" value={metricValue(p.latest, "load")} unit="" />
        <Gauge label="Connections" value={metricValue(p.latest, "connections")} unit="" series={series("connections")} />
        {metricValue(p.latest, "tls_handshake_ms") !== null ? <Gauge label="TLS handshake" value={metricValue(p.latest, "tls_handshake_ms")} unit=" ms" series={series("tls_handshake_ms")} /> : null}
        {metricValue(p.latest, "hsm_latency_ms") !== null ? <Gauge label="HSM latency" value={metricValue(p.latest, "hsm_latency_ms")} unit=" ms" /> : null}
      </div>
      {p.state === "NOT_SAMPLED" ? <div style={{ fontSize: 12, color: "var(--amber)", marginBottom: 12 }}>{p.meaning}</div> : null}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 12 }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 6 }}>Running services <span style={{ color: "var(--faint)", fontWeight: 500 }}>{host.counts.running_services} of {host.counts.services}</span></div>
          <ul aria-label="Services" style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 6 }}>
            {host.services.map((s) => (
              <li key={s.name} style={{ fontSize: 12, padding: "6px 8px", borderRadius: 6, background: "var(--panel-2)" }}>
                <span style={{ color: s.running ? "var(--green)" : "var(--faint)" }}>●</span> <b>{s.name}</b>
                <span style={{ color: "var(--faint)", fontFamily: "var(--mono)", fontSize: 11 }}> {s.executable}{s.user ? ` · ${s.user}` : ""}{s.listens_on ? ` · ${s.listens_on}` : ""}</span>
                {s.libraries.length ? <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 2 }}>loads {s.libraries.join(", ")}</div> : null}
              </li>
            ))}
          </ul>
        </div>
        <div>
          <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 6 }}>Listening <span style={{ color: "var(--faint)", fontWeight: 500 }}>{host.counts.exposed_listeners} exposed of {host.counts.listeners}</span></div>
          <table aria-label="Listeners" style={{ width: "100%", borderCollapse: "collapse", fontSize: 11.5 }}>
            <tbody>
              {host.listeners.map((l) => (
                <tr key={l.name} style={{ borderTop: "1px solid var(--line)" }}>
                  <td style={{ padding: "4px 6px 4px 0", fontFamily: "var(--mono)" }}>{l.port}/{l.protocol}</td>
                  <td style={{ padding: "4px 6px" }}>{l.process ?? "—"}</td>
                  <td style={{ padding: "4px 0", textAlign: "right", color: l.loopback_only ? "var(--faint)" : "var(--amber)" }}>
                    {l.loopback_only ? "loopback" : "exposed"}{l.tls_version ? ` · ${l.tls_version}` : ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div>
          <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 6 }}>Crypto libraries <span style={{ color: "var(--faint)", fontWeight: 500 }}>{host.counts.loaded_libraries} loaded of {host.counts.libraries}</span></div>
          <ul aria-label="Libraries" style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 4, fontSize: 12 }}>
            {host.libraries.map((l, i) => (
              <li key={`${l.path}-${i}`}>
                <b>{l.name}</b> <span style={{ fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--faint)" }}>{l.path}</span>
                <div style={{ fontSize: 11, color: l.loaded ? "var(--green)" : "var(--faint)" }}>
                  {l.loaded ? `loaded by ${l.loaded_by.join(", ") || "a running process"}` : "installed, not seen loaded"}
                </div>
              </li>
            ))}
          </ul>
        </div>
        <div>
          <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 6 }}>Certificates & keys</div>
          <ul aria-label="Certificates and keys" style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 4, fontSize: 12 }}>
            {host.certificates.map((c, i) => (
              <li key={`c-${i}`}>
                <b>{c.name}</b> <span style={{ color: "var(--dim)" }}>{c.algorithm}{c.key_size ? `-${c.key_size}` : ""}</span>
                <div style={{ fontSize: 11, color: c.days_left !== null && c.days_left <= 30 ? "var(--red)" : "var(--faint)" }}>
                  {c.days_left === null ? "expiry unknown" : c.days_left < 0 ? `expired ${-c.days_left} days ago` : `expires in ${c.days_left} days`}
                </div>
              </li>
            ))}
            {host.keys.map((k, i) => (
              <li key={`k-${i}`}><b>{k.name}</b> <span style={{ color: "var(--dim)" }}>{k.algorithm}{k.key_size ? ` ${k.key_size}-bit` : ""}</span></li>
            ))}
          </ul>
        </div>
      </div>

      <div style={{ marginTop: 14 }}>
        <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 6 }}>Algorithms on this host</div>
        <div aria-label="Algorithms" style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {host.algorithms.map((a) => (
            <span key={a.algorithm} title={`${VERDICT_LABEL[a.verdict] ?? a.verdict} · ${a.assets.join(", ")}`} style={{
              fontSize: 11.5, padding: "3px 9px", borderRadius: 99, fontFamily: "var(--mono)",
              color: VERDICT_COLOR[a.verdict] ?? "var(--dim)", border: `1px solid color-mix(in srgb, ${VERDICT_COLOR[a.verdict] ?? "var(--line)"} 45%, var(--line))`,
            }}>{a.algorithm} · {VERDICT_LABEL[a.verdict] ?? a.verdict}</span>
          ))}
          {host.algorithms.length === 0 ? <span style={{ fontSize: 12, color: "var(--faint)" }}>no algorithm recorded</span> : null}
        </div>
        <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 8 }}>
          {host.runtime_evidence} runtime observation(s) on this host ·{" "}
          <Link to={`/priorities`} style={{ color: "var(--cyan)" }}>its weaknesses in Priorities →</Link>
        </div>
      </div>
    </section>
  );
}

export default function Runtime() {
  const live = useLive<OpsHosts>(apiOpsHosts, 15000);
  const { data, state, error, refresh } = live;
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(null);

  const hosts = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data?.hosts ?? []).filter((h) => !q || [h.agent, h.host.name, h.host.fqdn, h.system?.name, ...h.host.ip_addresses]
      .some((v) => String(v ?? "").toLowerCase().includes(q)));
  }, [data, query]);
  useEffect(() => {
    if (hosts.length && (!selected || !hosts.some((h) => h.agent === selected))) setSelected(hosts[0].agent);
  }, [hosts, selected]);
  const current = hosts.find((h) => h.agent === selected) ?? null;
  const t = data?.totals ?? {};

  return (
    <>
      <OpsHeader
        crumb="Operations / Runtime hosts"
        title="Runtime hosts"
        icon={<IconHardware size={18} />}
        sub="Every bank server an agent observed, live: what runs on it, which crypto libraries its processes have loaded, the certificates, keys and algorithms on it, and its signed load samples."
        right={<LiveBar live={live} />}
      />
      {state !== "ready" || !data ? (
        <OpsLoadStates state={state} error={error} refresh={refresh} what="Runtime hosts" />
      ) : (
        <>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 14 }}>
            <KpiTile label="Hosts" ariaLabel="Hosts" value={t.hosts ?? 0} sub={`${t.sampled ?? 0} with a fresh performance sample`} />
            <KpiTile label="Running services" ariaLabel="Running services" value={t.running_services ?? 0} sub="seen running by the agents" />
            <KpiTile label="Loaded crypto libraries" ariaLabel="Loaded crypto libraries" value={t.loaded_libraries ?? 0} sub="mapped into a running process" />
            <KpiTile label="Quantum-vulnerable" ariaLabel="Quantum-vulnerable algorithms" value={t.quantum_vulnerable ?? 0}
              color={(t.quantum_vulnerable ?? 0) ? "var(--red)" : "var(--green)"} sub="algorithm uses across hosts" />
            <KpiTile label="Runtime observations" ariaLabel="Runtime observations" value={t.runtime_evidence ?? 0} sub="facts read from live processes" />
          </div>
          <div style={{ display: "flex", gap: 14, flexWrap: "wrap", alignItems: "flex-start" }}>
            <section aria-label="Hosts" style={{ ...card, flex: "1 1 320px", minWidth: 280, maxWidth: 440 }}>
              <input aria-label="Search hosts" placeholder="Search host, IP, system…" value={query} onChange={(e) => setQuery(e.target.value)} style={{ ...inputStyle, width: "100%", marginBottom: 10, boxSizing: "border-box" }} />
              <div style={{ display: "grid", gap: 6 }}>
                {hosts.map((h) => {
                  const cpu = metricValue(h.performance.latest, "cpu_pct");
                  const ram = metricValue(h.performance.latest, "ram_pct");
                  const active = h.agent === selected;
                  return (
                    <button key={h.agent} type="button" aria-pressed={active} aria-label={`Select ${h.host.name ?? h.agent}`} onClick={() => setSelected(h.agent)}
                      style={{ textAlign: "left", padding: 10, borderRadius: "var(--r)", cursor: "pointer", font: "inherit", color: "inherit",
                               background: active ? "color-mix(in srgb, var(--cyan) 10%, var(--panel-2))" : "var(--panel-2)",
                               border: `1px solid ${active ? "var(--cyan)" : "var(--line)"}` }}>
                      <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                        <span style={{ fontWeight: 700, fontSize: 12.5 }}>{h.host.name ?? h.agent}</span>
                        <LivenessPill state={h.liveness.state} />
                      </div>
                      <div style={{ fontSize: 11, color: "var(--dim)" }}>{h.system?.name ?? "no system"} · {h.host.ip_addresses[0] ?? ""}</div>
                      <div style={{ display: "flex", gap: 12, marginTop: 6, fontSize: 11, fontFamily: "var(--mono)", alignItems: "center" }}>
                        <span>CPU <b style={{ color: pctColor(cpu) }}>{cpu === null ? "—" : `${cpu.toFixed(0)}%`}</b></span>
                        <span>RAM <b style={{ color: pctColor(ram) }}>{ram === null ? "—" : `${ram.toFixed(0)}%`}</b></span>
                        <span style={{ color: h.counts.quantum_vulnerable ? "var(--red)" : "var(--faint)" }}>{h.counts.quantum_vulnerable} vuln</span>
                        <span style={{ marginLeft: "auto" }}><MiniSpark points={(h.performance.series?.cpu_pct ?? []).map((x) => x[1])} max={100} color={pctColor(cpu)} label={`CPU of ${h.agent}`} width={70} height={18} /></span>
                      </div>
                    </button>
                  );
                })}
                {hosts.length === 0 ? <div style={{ fontSize: 12.5, color: "var(--dim)" }}>No host matches.</div> : null}
              </div>
            </section>
            {current ? <HostDetail host={current} /> : null}
          </div>
        </>
      )}
      <Disclosure title="Runtime crypto sensors" sub="eBPF and adapter-based runtime crypto events, their scope and risk — the sensor path, separate from the agents' host observations above.">
        <RuntimeSensors embedded />
      </Disclosure>
    </>
  );
}
