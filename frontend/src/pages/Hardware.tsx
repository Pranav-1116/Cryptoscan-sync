import React, { useMemo, useState } from "react";
import { Panel, Badge, Table, PageHead, Tabs, Drawer } from "../components/ui.jsx";
import KeyReconciliationPanel from "../components/KeyReconciliationPanel";
import { usePollingApi, useApi, LiveBadge } from "../lib/apiUi.jsx";
import { useRealtimeRefresh } from "../lib/realtime.js";
import {
  apiLiveInventory, apiHardwareCatalog, apiLiveScanStatus,
  LiveInventory, HardwareEntry, LiveHardwareDevice,
} from "../lib/api.js";

/* Hardware — real, live data from the hardware scanner (CPU/TPM/HSM/smart
   card / accelerator) via GET /api/v1/live-scan/inventory, enriched with the
   root-of-trust capability summary from /live-scan/status. Devices render as
   cards; click one for an HSM/TPM/accelerator detail drill-down. The canonical
   catalog (GET /api/v1/hardware/catalog) lists every device the scanner can
   name. Empty until a live scan runs — nothing is fabricated. */

const HW_STATUS_TONE: Record<string, string> = {
  DISALLOWED: "red", DEPRECATED: "amber", RESTRICTED: "amber",
  UNKNOWN: "", ALLOWED: "green", REQUIRED: "green",
};

const DEVICE_GLYPH: Record<string, string> = {
  CPU: "▦", TPM: "🔐", HSM: "⌬", SECURE_ELEMENT: "⚿", ACCELERATOR: "⚡",
};

export default function Hardware() {
  const inv = usePollingApi(apiLiveInventory, 8000);
  const data = (inv.data ?? null) as LiveInventory | null;
  const devices: LiveHardwareDevice[] = data?.hardware ?? [];
  const firmware = data?.firmware ?? [];
  const live = inv.source === "live";

  const stat = usePollingApi(apiLiveScanStatus, 8000);
  const hwSummary = (stat.data as { scanners?: { hardware?: { summary?: Record<string, unknown> } } } | null)
    ?.scanners?.hardware?.summary ?? {};
  useRealtimeRefresh(inv.run, stat.run);

  const cat = useApi(() => apiHardwareCatalog(), []);
  const catalog: HardwareEntry[] = useMemo(() => cat.data?.devices ?? [], [cat.data]);
  const hwCounts = cat.data?.status_counts ?? {};
  const [hwTab, setHwTab] = useState(0);
  const hwTabs = ["all", "root-of-trust", "hardware-keystore", "secure-element", "secure-enclave", "trusted-execution", "self-encrypting-drive", "management-controller", "crypto-accelerator"];
  const catalogFiltered = useMemo(() => {
    const c = hwTabs[hwTab];
    return catalog
      .filter((d) => (c === "all" ? true : d.category === c))
      .sort((a, b) => String(a.device).localeCompare(String(b.device)));
  }, [catalog, hwTab, hwTabs]);

  const [sel, setSel] = useState<LiveHardwareDevice | null>(null);

  // Root-of-trust capability cells from the live hardware scanner summary.
  const rotCells: Array<{ k: string; present: boolean; v: string }> = [
    { k: "AES-NI acceleration", present: !!hwSummary.aes_ni, v: hwSummary.aes_ni ? "present" : "absent" },
    { k: "hardware RNG", present: !!hwSummary.hw_rng, v: hwSummary.hw_rng ? "present" : "absent" },
    { k: "TPM", present: !!hwSummary.tpm_present, v: hwSummary.tpm_present ? (String(hwSummary.tpm_version ?? "present")) : "absent" },
    { k: "HSM", present: !!hwSummary.hsm_present, v: hwSummary.hsm_present ? "present" : "absent" },
  ];
  const cpuModel = (hwSummary.cpu as string) || (devices.find((d) => d.type === "CPU")?.vendor) || "—";

  return (
    <>
      <PageHead
        crumb="discovery / hardware"
        title="Hardware root of trust"
        sub="CPU · TPM · HSM · secure elements · crypto accelerators · firmware (live hardware scanner)"
        right={
          <>
            {live && <LiveBadge source="live" label={data?.generated_at ? `LIVE · ${new Date(data.generated_at).toLocaleTimeString()}` : "LIVE"} />}
            <Badge tone={devices.length ? "green" : ""}><span className="dot" /> {devices.length} devices</Badge>
          </>
        }
      />

      {/* ── root-of-trust capability strip ───────────────────────────── */}
      <Panel title="Root of trust" sub="hardware-backed cryptographic primitives reported by the live scan">
        <div className="rot-strip">
          {rotCells.map((cell) => (
            <div key={cell.k} className={`rot-cell ${cell.present ? "present" : "absent"}`}>
              <span className="rot-k">{cell.k}</span>
              <span className={`rot-v ${cell.present ? "yes" : "no"}`}>
                {cell.present ? "✓ " : ""}{cell.v}
              </span>
            </div>
          ))}
        </div>
        <div className="mono" style={{ fontSize: 12, color: "var(--dim)", marginTop: 12 }}>
          <span className="faint">host:</span> {String(hwSummary.host ?? data?.host ?? "—")} ·{" "}
          <span className="faint">cpu:</span> {cpuModel}
        </div>
      </Panel>

      {/* ── discovered devices (cards → detail drawer) ───────────────── */}
      <Panel title="Discovered hardware devices" sub="click a device for HSM / TPM / accelerator detail" className="mt">
        {devices.length === 0 ? (
          <div className="dim" style={{ fontSize: 13 }}>
            No hardware data yet — run a live scan in Operations → Realtime scanners.
          </div>
        ) : (
          <div className="hw-grid">
            {devices.map((h, i) => (
              <button key={`${h.id}-${i}`} className="hw-card" onClick={() => setSel(h)}>
                <div className="hw-top">
                  <span className="hw-type">{DEVICE_GLYPH[h.type] ?? "▣"} {h.type}</span>
                  <Badge tone={String(h.status).startsWith("middleware") ? "amber" : "green"}>{h.status}</Badge>
                </div>
                <div className="hw-id">{h.id}</div>
                <div className="hw-ven">{h.vendor || "—"}</div>
                <div className="hw-fw">fw: {h.firmware || "—"}</div>
                <div className="hw-caps">
                  {h.caps.length ? h.caps.map((c) => <span key={c} className="cap-chip">{c}</span>)
                    : <span className="faint" style={{ fontSize: 11 }}>no capabilities reported</span>}
                </div>
              </button>
            ))}
          </div>
        )}
      </Panel>

      {/* ── firmware vs baseline ─────────────────────────────────────── */}
      <Panel title="Firmware vs baseline" sub="CPU microcode and TPM firmware" className="mt">
        <Table
          head={["device", "kind", "version", "status"]}
          rows={firmware.map((f) => [
            <span className="mono">{f.device}</span>,
            f.kind,
            <span className="num">{f.version}</span>,
            String(f.status).startsWith("DRIFT") ? <Badge tone="red">{f.status}</Badge> : <Badge tone="green">{f.status}</Badge>,
          ])}
        />
        {!firmware.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            No firmware baseline data yet — appears after a live scan.
          </div>
        )}
      </Panel>

      <KeyReconciliationPanel />

      <Panel title="Hardware timeline" sub="every change is evidence-linked" className="mt">
        {firmware.length ? (
          <div className="timeline">
            {firmware.slice(0, 8).map((f, i) => (
              <div className="tl" key={`${f.device}-${i}`}>
                <span className="dim" style={{ fontSize: 13 }}>{f.kind} {f.version} — {f.device} · {f.status}</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="dim" style={{ fontSize: 13 }}>
            No hardware events yet — CPU/TPM/HSM discoveries and firmware changes appear here after a live scan.
          </div>
        )}
      </Panel>

      {/* ── canonical catalog ────────────────────────────────────────── */}
      <Panel
        title="Hardware security catalog"
        sub="canonical registry — every TPM / HSM / secure element / enclave the scanner can name, with verdict"
        className="mt"
      >
        <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
          {(["REQUIRED", "ALLOWED", "RESTRICTED", "DEPRECATED", "DISALLOWED"] as const).map((s) => (
            <Badge key={s} tone={HW_STATUS_TONE[s]}>{s}: {hwCounts[s] ?? 0}</Badge>
          ))}
          <LiveBadge source={cat.source} label={cat.source === "live" ? "REGISTRY LIVE" : "REGISTRY OFFLINE"} />
        </div>
        <Tabs tabs={hwTabs.map((t) => (t === "all" ? "all" : t.replace(/-/g, " ")))} active={hwTab} onChange={setHwTab} />
        <Table
          head={["device", "category", "manufacturer", "attestation", "PQC-ready", "status", "notes"]}
          rows={catalogFiltered.map((d) => [
            <span className="mono">{d.device}</span>,
            <Badge tone="violet">{d.category}</Badge>,
            d.manufacturer || "—",
            d.attestation ? <Badge tone="cyan">attested</Badge> : "—",
            d.quantum_resistant ? <Badge tone="green">yes</Badge> : "—",
            <Badge tone={HW_STATUS_TONE[d.status] ?? ""}>{d.status}</Badge>,
            <span className="dim" style={{ fontSize: 12 }}>{d.risk_reason || d.notes || ""}</span>,
          ])}
        />
        {!catalogFiltered.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            {cat.source === "live" ? "No devices in this category." : "Backend offline — hardware catalog unavailable."}
          </div>
        )}
      </Panel>

      {/* ── device detail drawer ─────────────────────────────────────── */}
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
              ? <div className="hw-caps">{sel.caps.map((c) => <Badge key={c} tone="cyan">{c}</Badge>)}</div>
              : <span className="faint" style={{ fontSize: 13 }}>no capabilities reported</span>}
          </Panel>
          <Panel title="Evidence" sub="linked attestation artifacts" frame className="mt">
            <a href="#/evidence" className="mono" style={{ fontSize: 12 }}>open evidence chain →</a>
          </Panel>
        </Drawer>
      )}
    </>
  );
}
