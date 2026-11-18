import { Link } from "react-router-dom";
import React, { useMemo, useState } from "react";
import { Panel, Badge, Table, Tabs, Drawer, Bar, Ring } from "../components/ui.jsx";
import KeyReconciliationPanel from "../components/KeyReconciliationPanel";
import { usePollingApi, useApi, LiveBadge } from "../lib/apiUi.jsx";
import { useChannelRefresh } from "../lib/realtime.js";
import { StatusMark } from "../components/icons";
import { IconHardware, IconSecret, IconCrypto, IconSecurity, IconAccelerator, IconComponent, ICON_MD, IconTarget, type Icon } from "../components/icons";
import {
  apiLiveInventory, apiHardwareCatalog, apiLiveScanStatus,
  LiveInventory, HardwareEntry, LiveHardwareDevice,
} from "../lib/api.js";
import DomainCrossNav from "../components/DomainCrossNav";

/* Hardware — immersive visual upgrade: hero + KPI cards + analytics
   Preserves live hardware inventory, root-of-trust, firmware, catalog. */

const HW_STATUS_TONE: Record<string, string> = {
  DISALLOWED: "red", DEPRECATED: "amber", RESTRICTED: "amber",
  UNKNOWN: "", ALLOWED: "green", REQUIRED: "green",
};

const DEVICE_ICON: Record<string, Icon> = {
  CPU: IconHardware, TPM: IconSecret, HSM: IconCrypto,
  SECURE_ELEMENT: IconSecurity, ACCELERATOR: IconAccelerator,
};

export default function Hardware() {
  const inv = usePollingApi(apiLiveInventory, 8000, [], { channels: ["inventory", "crypto"] });
  const data = (inv.data ?? null) as LiveInventory | null;
  const devices: LiveHardwareDevice[] = data?.hardware ?? [];
  const firmware = data?.firmware ?? [];
  const live = inv.source === "live";

  const stat = usePollingApi(apiLiveScanStatus, 8000, [], { channels: ["estate", "inventory"] });
  const hwSummary = (stat.data as { scanners?: { hardware?: { summary?: Record<string, unknown> } } } | null)
    ?.scanners?.hardware?.summary ?? {} as Record<string, any>;
  useChannelRefresh(["inventory", "crypto", "estate"], [inv.run, stat.run]);

  const cat = useApi(() => apiHardwareCatalog(), []);
  const catalog: HardwareEntry[] = useMemo(() => cat.data?.devices ?? [], [cat.data]);
  const hwCounts = cat.data?.status_counts ?? {} as Record<string, number>;
  const [hwTab, setHwTab] = useState(0);
  const hwTabs = ["all", "root-of-trust", "hardware-keystore", "secure-element", "secure-enclave", "trusted-execution", "self-encrypting-drive", "management-controller", "crypto-accelerator"];
  const catalogFiltered = useMemo(() => {
    const c = hwTabs[hwTab];
    return catalog
      .filter((d) => (c === "all" ? true : d.category === c))
      .sort((a, b) => String(a.device).localeCompare(String(b.device)));
  }, [catalog, hwTab]);

  const [sel, setSel] = useState<LiveHardwareDevice | null>(null);

  // The hardware scanner reports these four primitives in its summary. With no
  // summary (no cycle has run) the answer is "not measured" — calling the host
  // "absent" would be a claim about hardware nobody looked at.
  const hwMeasured = stat.source === "live" && Object.keys(hwSummary).length > 0;
  const rotCells: Array<{ k: string; present: boolean | null; v: string; icon: Icon }> = [
    { k: "AES-NI acceleration", present: hwMeasured ? !!hwSummary.aes_ni : null, v: hwMeasured ? (hwSummary.aes_ni ? "present" : "absent") : "not measured", icon: IconAccelerator },
    { k: "hardware RNG", present: hwMeasured ? !!hwSummary.hw_rng : null, v: hwMeasured ? (hwSummary.hw_rng ? "present" : "absent") : "not measured", icon: IconSecret },
    { k: "TPM", present: hwMeasured ? !!hwSummary.tpm_present : null, v: hwMeasured ? (hwSummary.tpm_present ? String(hwSummary.tpm_version ?? "present") : "absent") : "not measured", icon: IconSecurity },
    { k: "HSM", present: hwMeasured ? !!hwSummary.hsm_present : null, v: hwMeasured ? (hwSummary.hsm_present ? "present" : "absent") : "not measured", icon: IconCrypto },
  ];
  const cpuModel = (hwSummary.cpu as string) || (devices.find((d) => d.type === "CPU")?.vendor) || "—";
  const rotPresent = rotCells.filter(c => c.present === true).length;
  const deviceTypes = useMemo(() => {
    const m: Record<string, number> = {};
    for (const d of devices) m[d.type] = (m[d.type] ?? 0) + 1;
    return m;
  }, [devices]);
  const firmwareOk = firmware.filter(f => !String(f.status).startsWith("DRIFT")).length;
  const firmwareDrift = firmware.filter(f => String(f.status).startsWith("DRIFT")).length;
  const hsmCount = devices.filter(d => d.type === "HSM").length;
  const tpmCount = devices.filter(d => d.type === "TPM").length;

  // KPI calculations
  const totalDevices = devices.length;
  const totalCatalog = catalog.length;
  const requiredCount = hwCounts["REQUIRED"] ?? 0;
  const allowedCount = hwCounts["ALLOWED"] ?? 0;

  return (
    <div style={{ maxWidth: 1280, margin: "0 auto", padding: "10px 0 60px" }}>
      <DomainCrossNav current="hardware" />
      {/* ── HERO ─────────────────────────────────────────────── */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 16, marginBottom: 16 }}>
        <div style={{ flex: "1 1 460px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--amber) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--amber) 35%, var(--line))", fontSize: 11, fontFamily: "var(--mono)", color: "var(--amber)", letterSpacing: "0.06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: live ? "var(--green)" : "var(--amber)" }} /> DISCOVERY · HARDWARE · ROOT OF TRUST
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--amber)", color: "#fff" }}><IconHardware size={18} /></span>
            Hardware root of trust
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 620 }}>
            <b style={{ color: "var(--text)" }}>{live && data ? `${totalDevices} live devices` : "Hardware inventory not read"}</b> · CPU · TPM · HSM · secure elements · accelerators — from <span style={{ color: "var(--amber)", fontFamily: "var(--mono)" }}>live hardware scanner</span> {live && data?.generated_at ? `· ${new Date(data.generated_at as string).toLocaleTimeString()}` : "· awaiting scan"}.
          </p>
          <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap", alignItems: "center" }}>
            <span className="kicker" style={{ fontSize: 10 }}>LIVE SCAN INVENTORY</span>
            <span style={{ color: "var(--line-strong)" }}>·</span>
            <span style={{ fontSize: 11, color: "var(--dim)" }}>{tpmCount} TPM · {hsmCount} HSM · {firmware.length} firmware baselines</span>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          <Panel style={{ padding: "10px 14px", minWidth: 160, display: "flex", alignItems: "center", gap: 12 }}>
            <Ring pct={hwMeasured ? rotPresent / 4 : 0} label={hwMeasured ? `${rotPresent}/4` : "—"} sub="root of trust" tone={hwMeasured ? (rotPresent >= 3 ? "green" : "amber") : "slate"} />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>LIVE ESTATE</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 130, lineHeight: 1.4 }}>
                {live && data ? `${Object.keys(deviceTypes).length} types · ${hwMeasured ? `${rotPresent}/4 RoT present` : "RoT not measured"}` : "inventory read did not return"}
              </div>
              <div style={{ marginTop: 6 }}><Bar value={hwMeasured ? rotPresent / 4 : 0} tone={hwMeasured ? (rotPresent >= 3 ? "green" : "amber") : "slate"} /></div>
            </div>
          </Panel>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <Link to="/live-scanners" className="btn primary" style={{ fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)", textDecoration: "none", textAlign: "center" }}>Run hardware scan</Link>
            <div style={{ display: "flex", gap: 6, justifyContent: "center" }}>
              {live ? <LiveBadge source="live" label="LIVE" /> : <Badge tone="amber">OFFLINE</Badge>}
              <Badge tone={totalDevices ? "green" : ""}>{totalDevices} devices</Badge>
            </div>
            <span style={{ fontSize: 10, color: "var(--faint)", textAlign: "center", fontFamily: "var(--mono)" }}>{String(hwSummary.host ?? data?.host ?? "").slice(0, 24) || "no host"}</span>
          </div>
        </div>
      </div>

      {/* ── KPI STRIP ───────────────────────────────────────── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))", gap: 12, marginBottom: 14 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--amber)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconHardware size={12} /> LIVE DEVICES</div>
              <div style={{ fontSize: 30, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{totalDevices}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>{Object.keys(deviceTypes).join(" · ") || "No discovery yet"}</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--amber) 14%, transparent)", border: "1px solid color-mix(in srgb, var(--amber) 35%, var(--line))", color: "var(--amber)" }}><IconHardware size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <Bar value={totalDevices ? Math.min(1, totalDevices / 10) : 0} tone="amber" />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>{totalDevices ? "Hardware scanner inventory" : "Awaiting live scan"}</div>
          </div>
        </div>

        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${rotPresent >= 3 ? "var(--green)" : rotPresent >= 2 ? "var(--amber)" : "var(--slate)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>ROOT OF TRUST</div>
              <div style={{ fontSize: 30, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1, color: hwMeasured ? "var(--text)" : "var(--slate)" }}>{hwMeasured ? `${rotPresent}/4` : "—"}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>{!hwMeasured ? "no hardware summary yet" : rotPresent === 4 ? "Complete" : rotPresent >= 2 ? "Partial" : "Minimal"}</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: rotPresent >= 3 ? "color-mix(in srgb, var(--green) 14%, transparent)" : "var(--panel-2)", border: `1px solid color-mix(in srgb, ${rotPresent >= 3 ? "var(--green)" : "var(--line)"} 35%, var(--line))`, color: rotPresent >= 3 ? "var(--green)" : "var(--faint)" }}><IconSecurity size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <Bar value={hwMeasured ? rotPresent / 4 : 0} tone={rotPresent >= 3 ? "green" : rotPresent >= 2 ? "amber" : "slate"} />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>AES-NI · RNG · TPM · HSM</div>
          </div>
        </div>

        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${firmwareDrift ? "var(--red)" : "var(--green)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>FIRMWARE BASELINE</div>
              <div style={{ fontSize: 30, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{firmware.length}</div>
              <div style={{ fontSize: 12, color: firmwareDrift ? "var(--red)" : "var(--dim)" }}>{firmwareDrift ? `${firmwareDrift} drift` : firmwareOk ? `${firmwareOk} aligned` : "No baseline"}</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: firmwareDrift ? "color-mix(in srgb, var(--red) 14%, transparent)" : "color-mix(in srgb, var(--green) 14%, transparent)", border: `1px solid color-mix(in srgb, ${firmwareDrift ? "var(--red)" : "var(--green)"} 35%, var(--line))`, color: firmwareDrift ? "var(--red)" : "var(--green)" }}><IconTarget size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", height: 6, borderRadius: 99, overflow: "hidden", border: "1px solid var(--line)" }}>
              <div style={{ width: `${firmware.length ? (firmwareOk / firmware.length) * 100 : 0}%`, background: "var(--green)" }} />
              <div style={{ flex: 1, background: firmwareDrift ? "var(--red)" : "var(--line)" }} />
            </div>
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>CPU microcode · TPM fw</div>
          </div>
        </div>

        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--violet)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>SECURITY CATALOG</div>
              <div style={{ fontSize: 30, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{totalCatalog}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>{requiredCount} required · {allowedCount} allowed</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--violet) 14%, transparent)", border: "1px solid color-mix(in srgb, var(--violet) 35%, var(--line))", color: "var(--violet)" }}><IconComponent size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
              {["REQUIRED", "ALLOWED", "RESTRICTED", "DEPRECATED", "DISALLOWED"].map(s => (
                <span key={s} style={{ fontSize: 10, padding: "2px 6px", borderRadius: 999, background: "var(--panel-2)", border: "1px solid var(--line)", color: "var(--dim)" }}>{s.slice(0, 3)} {hwCounts[s] ?? 0}</span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Root of trust — visual cards */}
      <Panel title="Root of trust" sub={hwMeasured ? `${rotPresent} of 4 hardware primitives present — live hardware scanner` : "No hardware summary in the last cycle — nothing measured"}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 10 }}>
          {rotCells.map((cell) => (
            <div key={cell.k} style={{
              padding: "12px 14px",
              border: `1px solid ${cell.present ? "color-mix(in srgb, var(--green) 30%, var(--line))" : cell.present === false ? "color-mix(in srgb, var(--red) 24%, var(--line))" : "var(--line)"}`,
              borderTop: `2px solid ${cell.present ? "var(--green)" : cell.present === false ? "var(--red)" : "var(--line-strong)"}`,
              borderRadius: "var(--r)",
              background: cell.present ? "color-mix(in srgb, var(--green) 6%, var(--panel))" : "var(--panel)",
              display: "flex",
              flexDirection: "column",
              gap: 8,
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ color: cell.present ? "var(--green)" : cell.present === false ? "var(--red)" : "var(--faint)", lineHeight: 0 }}><cell.icon size={16} /></span>
                <span style={{
                  width: 8, height: 8, borderRadius: 99,
                  background: cell.present ? "var(--green)" : cell.present === false ? "var(--red)" : "var(--faint)",
                  boxShadow: cell.present ? "0 0 6px var(--green)" : "none",
                }} />
              </div>
              <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: ".04em", color: "var(--faint)" }}>{cell.k.toUpperCase()}</div>
              <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13, fontWeight: 700, color: cell.present ? "var(--green)" : cell.present === false ? "var(--red)" : "var(--faint)" }}>
                {cell.present ? <StatusMark ok muted /> : null}{cell.v}
              </div>
            </div>
          ))}
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 10, flexWrap: "wrap", fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)" }}>
          <span style={{ padding: "3px 8px", borderRadius: 999, background: "var(--panel-2)", border: "1px solid var(--line)" }}>host <b style={{ color: "var(--text)" }}>{String(hwSummary.host ?? data?.host ?? "—")}</b></span>
          <span style={{ padding: "3px 8px", borderRadius: 999, background: "var(--panel-2)", border: "1px solid var(--line)" }}>cpu <b style={{ color: "var(--text)" }}>{cpuModel}</b></span>
          <span style={{ marginLeft: "auto", color: "var(--faint)" }}>{hwMeasured ? `${rotPresent}/4 primitives · ` : ""}{devices.length} devices</span>
        </div>
      </Panel>

      {/* Discovered devices */}
      <Panel title="Discovered hardware devices" sub={`${devices.length} inventoried · click a card for HSM / TPM / accelerator detail`} className="mt">
        {devices.length === 0 ? (
          <div style={{ padding: "24px", textAlign: "center", border: "1px dashed var(--line)", borderRadius: "var(--r)", background: "var(--panel)" }}>
            <div style={{ fontSize: 13, color: "var(--faint)" }}>No hardware data yet</div>
            <div style={{ fontSize: 12, color: "var(--dim)", marginTop: 4 }}>Run a live scan in <Link to="/live-scanners" style={{ color: "var(--amber)" }}>Operations → Realtime scanners</Link> to populate this estate.</div>
          </div>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))", gap: 10 }}>
            {devices.map((h, i) => {
              const tint = h.type === "HSM" ? "var(--violet)" : h.type === "TPM" ? "var(--amber)" : h.type === "CPU" ? "var(--accent)" : "var(--slate)";
              return (
                <button key={`${h.id}-${i}`} onClick={() => setSel(h)} style={{
                  textAlign: "left",
                  padding: "12px 14px",
                  border: "1px solid var(--line)",
                  borderTop: `2px solid ${tint}`,
                  borderRadius: "var(--r)",
                  background: "var(--panel)",
                  cursor: "pointer",
                  display: "flex",
                  flexDirection: "column",
                  gap: 6,
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11, fontWeight: 700, color: tint }}>
                      {(() => { const I = DEVICE_ICON[h.type] ?? IconComponent; return <I size={14} />; })()} {h.type}
                    </span>
                    <Badge tone={String(h.status).startsWith("middleware") ? "amber" : "green"}>{h.status}</Badge>
                  </div>
                  <div style={{ fontFamily: "var(--mono)", fontSize: 12, fontWeight: 700, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{h.id}</div>
                  <div style={{ fontSize: 11, color: "var(--dim)" }}>{h.vendor || "—"} · fw {h.firmware || "—"}</div>
                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 4 }}>
                    {h.caps.length ? h.caps.slice(0, 4).map((c) => (
                      <span key={c} style={{ fontSize: 10, padding: "2px 6px", borderRadius: 999, background: "color-mix(in srgb, var(--amber) 10%, transparent)", border: "1px solid var(--line)", color: "var(--dim)" }}>{c}</span>
                    )) : <span style={{ fontSize: 11, color: "var(--faint)" }}>no capabilities reported</span>}
                    {h.caps.length > 4 && <span style={{ fontSize: 10, color: "var(--faint)" }}>+{h.caps.length - 4}</span>}
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </Panel>

      {/* Firmware */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))", gap: 12, marginTop: 12 }}>
        <Panel title="Firmware vs baseline" sub="CPU microcode and TPM firmware — drift is a security gap">
          <Table
            head={["device", "kind", "version", "status"]}
            rows={firmware.map((f) => [
              <span className="mono" style={{ fontSize: 12 }}>{f.device}</span>,
              <span style={{ fontSize: 12 }}>{f.kind}</span>,
              <span className="num" style={{ fontSize: 12 }}>{f.version}</span>,
              String(f.status).startsWith("DRIFT") ? <Badge tone="red">{f.status}</Badge> : <Badge tone="green">{f.status}</Badge>,
            ])}
          />
          {!firmware.length && (
            <div style={{ fontSize: 12, color: "var(--faint)", marginTop: 8, padding: "10px", border: "1px dashed var(--line)", borderRadius: "var(--r)", textAlign: "center" }}>
              No firmware baseline yet — appears after a live scan.
            </div>
          )}
        </Panel>
        <Panel title="Hardware timeline" sub="Every change is evidence-linked">
          {firmware.length ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
              {firmware.slice(0, 8).map((f, i) => (
                <div key={`${f.device}-${i}`} style={{ display: "flex", gap: 10, padding: "8px 0", borderTop: i ? "1px solid var(--line)" : "none", alignItems: "center" }}>
                  <span style={{ width: 8, height: 8, borderRadius: 99, background: String(f.status).startsWith("DRIFT") ? "var(--red)" : "var(--green)", flexShrink: 0 }} />
                  <span style={{ fontSize: 12, color: "var(--dim)" }}>{f.kind}</span>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 12, fontWeight: 600 }}>{f.version}</span>
                  <span style={{ fontSize: 11, color: "var(--faint)" }}>{f.device}</span>
                  <Badge tone={String(f.status).startsWith("DRIFT") ? "red" : "green"}>{f.status}</Badge>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ fontSize: 12, color: "var(--faint)", padding: "14px", textAlign: "center", border: "1px dashed var(--line)", borderRadius: "var(--r)" }}>
              No hardware events yet — CPU/TPM/HSM discoveries appear here after a scan.
            </div>
          )}
        </Panel>
      </div>

      <div style={{ marginTop: 12 }}>
        <KeyReconciliationPanel />
      </div>

      {/* Catalog */}
      <Panel
        title="Hardware security catalog"
        sub={`${catalog.length} known devices · verdict per device (REQUIRED / ALLOWED / RESTRICTED / DEPRECATED / DISALLOWED)`}
        className="mt"
      >
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10, alignItems: "center" }}>
          {(["REQUIRED", "ALLOWED", "RESTRICTED", "DEPRECATED", "DISALLOWED"] as const).map((s) => (
            <span key={s} style={{
              fontSize: 11, padding: "4px 10px", borderRadius: 999,
              background: s === "REQUIRED" || s === "ALLOWED" ? "color-mix(in srgb, var(--green) 12%, transparent)" : s === "DISALLOWED" || s === "DEPRECATED" ? "color-mix(in srgb, var(--red) 10%, transparent)" : "color-mix(in srgb, var(--amber) 10%, transparent)",
              border: `1px solid ${HW_STATUS_TONE[s] ? `var(--${HW_STATUS_TONE[s]})` : "var(--line)"}`,
              fontWeight: 600,
            }}>{s} <b>{hwCounts[s] ?? 0}</b></span>
          ))}
          <span style={{ marginLeft: "auto" }}><LiveBadge source={cat.source} label={cat.source === "live" ? "REGISTRY LIVE" : "REGISTRY OFFLINE"} /></span>
        </div>
        <Tabs tabs={hwTabs.map((t) => (t === "all" ? "all" : t.replace(/-/g, " ")))} active={hwTab} onChange={setHwTab} />
        <div style={{ marginTop: 10 }}>
          <Table
            head={["device", "category", "manufacturer", "attestation", "PQC-ready", "status", "notes"]}
            rows={catalogFiltered.map((d) => [
              <span className="mono" style={{ fontSize: 12 }}>{d.device}</span>,
              <Badge tone="violet">{d.category}</Badge>,
              <span style={{ fontSize: 12 }}>{d.manufacturer || "—"}</span>,
              d.attestation ? <Badge tone="cyan">attested</Badge> : <span style={{ color: "var(--faint)" }}>—</span>,
              d.quantum_resistant ? <Badge tone="green">yes</Badge> : <span style={{ color: "var(--faint)" }}>—</span>,
              <Badge tone={HW_STATUS_TONE[d.status] ?? ""}>{d.status}</Badge>,
              <span className="dim" style={{ fontSize: 12 }}>{d.risk_reason || d.notes || ""}</span>,
            ])}
          />
        </div>
        {!catalogFiltered.length && (
          <div style={{ fontSize: 12, color: "var(--faint)", marginTop: 8, padding: "10px", textAlign: "center", border: "1px dashed var(--line)", borderRadius: "var(--r)" }}>
            {cat.source === "live" ? "No devices in this category." : "Backend offline — hardware catalog unavailable."}
          </div>
        )}
      </Panel>

      {sel && (
        <Drawer
          title={sel.id}
          sub={`${sel.type} · ${sel.host}`}
          onClose={() => setSel(null)}
        >
          <div className="row" style={{ marginBottom: 16 }}>
            <Badge tone="violet">{sel.type}</Badge>
            <Badge tone={String(sel.status).startsWith("middleware") ? "amber" : "green"}>{sel.status}</Badge>
          </div>
          <div className="detail-kv">
            <span className="k">identifier</span><span className="v mono">{sel.id}</span>
            <span className="k">type</span><span className="v">{sel.type}</span>
            <span className="k">vendor</span><span className="v">{sel.vendor || "—"}</span>
            <span className="k">firmware</span><span className="v mono">{sel.firmware || "—"}</span>
            <span className="k">host</span><span className="v mono">{sel.host}</span>
          </div>
          <Panel title="Capabilities" sub="hardware-backed primitives exposed by this device" frame>
            {sel.caps.length
              ? <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>{sel.caps.map((c) => <Badge key={c} tone="cyan">{c}</Badge>)}</div>
              : <span className="faint" style={{ fontSize: 13 }}>no capabilities reported</span>}
          </Panel>
          <Panel title="Evidence" sub="linked attestation artifacts" frame className="mt">
            <Link to="/evidence" className="mono" style={{ fontSize: 12 }}>open evidence chain →</Link>
          </Panel>
        </Drawer>
      )}
    </div>
  );
}
