import React, { useMemo, useState } from "react";
import { Panel, Badge, Table, PageHead, Tabs } from "../components/ui.jsx";
import { usePollingApi, useApi, LiveBadge } from "../lib/apiUi.jsx";
import { apiLiveInventory, apiHardwareCatalog, LiveInventory, HardwareEntry } from "../lib/api.js";

/* Hardware — real, live data from the hardware scanner (CPU/TPM/HSM/smart
   card) via GET /api/v1/live-scan/inventory. Empty until a live scan runs.
   The bottom panel renders the canonical hardware-security catalog
   (GET /api/v1/hardware/catalog): every TPM/HSM/secure element/enclave the
   scanner can name, with verdict and attestation flags. */

const HW_STATUS_TONE: Record<string, string> = {
  DISALLOWED: "red",
  DEPRECATED: "amber",
  RESTRICTED: "amber",
  UNKNOWN: "",
  ALLOWED: "green",
  REQUIRED: "green",
};

export default function Hardware() {
  const inv = usePollingApi(apiLiveInventory, 8000);
  const data = (inv.data ?? null) as LiveInventory | null;
  const devices = data?.hardware ?? [];

  const cat = useApi(() => apiHardwareCatalog(), []);
  const catalog: HardwareEntry[] = useMemo(() => cat.data?.devices ?? [], [cat.data]);
  const hwCounts = cat.data?.status_counts ?? {};
  const [hwTab, setHwTab] = useState(0);
  const hwTabs = ["all", "root-of-trust", "hardware-keystore", "secure-element", "secure-enclave", "trusted-execution", "self-encrypting-drive", "management-controller"];
  const catalogFiltered = useMemo(() => {
    const c = hwTabs[hwTab];
    return catalog
      .filter((d) => (c === "all" ? true : d.category === c))
      .sort((a, b) => String(a.device).localeCompare(String(b.device)));
  }, [catalog, hwTab, hwTabs]);

  const firmware = data?.firmware ?? [];
  const live = inv.source === "live";

  return (
    <>
      <PageHead
        crumb="discovery / hardware"
        title="Hardware"
        sub="CPU · TPM · HSM · secure elements · crypto accelerators · firmware (live hardware scanner)"
        right={
          <>
            {live && <LiveBadge source="live" label={data?.generated_at ? `LIVE · ${new Date(data.generated_at).toLocaleTimeString()}` : "LIVE"} />}
            <Badge tone={devices.length ? "green" : ""}><span className="dot" /> {devices.length.toLocaleString()} DEVICES</Badge>
          </>
        }
      />
      <Panel title="CPU · TPM · HSM · secure elements" sub="capabilities and firmware from the live hardware scan">
        <Table
          head={["id", "type", "vendor", "firmware", "capabilities", "host", "status"]}
          rows={devices.map((h) => [
            <span className="mono">{h.id}</span>,
            <Badge tone="violet">{h.type}</Badge>,
            h.vendor || "—",
            <span className="num">{h.firmware}</span>,
            <span className="row">{h.caps.map((c) => <Badge key={c}>{c}</Badge>)}</span>,
            <span className="mono">{h.host}</span>,
            <Badge tone={h.status.startsWith("middleware") ? "amber" : "green"}>{h.status}</Badge>,
          ])}
        />
        {!devices.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            No hardware data yet — run a live scan in Operations → Realtime scanners.
          </div>
        )}
      </Panel>
      <Panel title="Firmware vs baseline" sub="CPU microcode and TPM firmware" className="mt">
        <Table
          head={["device", "kind", "version", "status"]}
          rows={firmware.map((f) => [
            <span className="mono">{f.device}</span>,
            f.kind,
            <span className="num">{f.version}</span>,
            f.status.startsWith("DRIFT") ? <Badge tone="red">{f.status}</Badge> : <Badge tone="green">{f.status}</Badge>,
          ])}
        />
      </Panel>
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
            {cat.source === "live"
              ? "No devices in this category."
              : "Backend offline — hardware catalog unavailable."}
          </div>
        )}
      </Panel>
    </>
  );
}
