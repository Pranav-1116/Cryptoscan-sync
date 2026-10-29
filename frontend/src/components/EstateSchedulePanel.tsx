import React, { useState } from "react";
import { usePrivateScopeCurrent } from "./PrivateScope";
import { usePollingApi } from "../lib/apiUi";
import { apiEstateCreateSchedule, apiEstateSchedules, getRoles } from "../lib/api";

const PERSISTED_PLANES = ["STATIC", "HARDWARE", "NETWORK", "RUNTIME", "PKI", "VENDOR"];

/** An approved cadence reprojects stored evidence; it never authorizes a collector. */
export default function EstateSchedulePanel() {
  const current = usePrivateScopeCurrent();
  const schedules = usePollingApi(apiEstateSchedules, 30000, [], { channels: ["estate"] });
  const canManage = getRoles().some(role => role === "superadmin" || role === "ciso");
  const [name, setName] = useState("");
  const [every, setEvery] = useState("6h");
  const [plane, setPlane] = useState("STATIC");
  const [scope, setScope] = useState("local");
  const [estate, setEstate] = useState("default");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const rows = schedules.source === "live" && Array.isArray(schedules.data?.schedules)
    ? schedules.data.schedules : null;

  const create = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy || !current()) return;
    setBusy(true); setMessage(""); setError("");
    try {
      const result = await apiEstateCreateSchedule({ name: name.trim(), every: every.trim(),
        planes: [plane], enabled: true, scope: scope.trim(), estate: estate.trim() });
      if (!current()) return;
      if (result.source !== "live" || result.ok !== true || !result.data?.id
        || result.data.name !== name.trim() || result.data.enabled !== true
        || !result.data.planes?.includes(plane)) {
        setError(`Schedule outcome unconfirmed (${result.error || "invalid receipt"}); inspect the retained list before retrying.`);
        return;
      }
      setMessage(`Projection schedule ${result.data.name} saved · ID ${result.data.id} · next due ${result.data.next_run_at}. No new collection was authorized.`);
      setName("");
      await schedules.run();
    } catch (cause) {
      if (current()) setError(`Schedule outcome unconfirmed (${cause instanceof Error ? cause.message : String(cause)}); inspect the retained list before retrying.`);
    } finally {
      if (current()) setBusy(false);
    }
  };

  return <section className="panel" aria-label="Evidence projection schedules" style={{ padding: 16, marginBottom: 16 }}>
    <h2 style={{ fontSize: 15, margin: "0 0 8px" }}>Evidence projection schedules</h2>
    <p style={{ color: "var(--dim)", fontSize: 12 }}>
      A cadence re-reads retained evidence; it does not scan source, probe endpoints, or contact cloud/HSM providers.
      Register and approve collection separately. A schedule with no stored observations proves no coverage.
    </p>
    {rows === null ? <p role="alert">Schedule list unavailable or incomplete; no absence inferred.</p>
      : rows.length === 0 ? <p role="status">No schedules in this estate. Nothing is reprojected.</p>
      : <div style={{ overflowX: "auto" }}><table>
        <thead><tr><th>Name</th><th>Planes</th><th>Next due</th><th>Last run</th><th>Coverage</th></tr></thead>
        <tbody>{rows.map(row => <tr key={row.id}>
          <td>{row.name} · {row.enabled ? "enabled" : "paused"}</td>
          <td>{row.planes?.join(", ") || "unqualified legacy scope"}</td>
          <td>{row.next_run_at || "—"}</td>
          <td>{row.last_run?.verdict || "NOT_RUN"}</td>
          <td>{row.last_run?.coverage_state || "UNKNOWN"}</td>
        </tr>)}</tbody>
      </table></div>}
    {canManage && <form onSubmit={event => void create(event)} style={{ marginTop: 14 }}>
      <p style={{ fontSize: 12, color: "var(--dim)" }}>Current monitor managers may enable a persisted-evidence projection. The server rechecks durable human authority and plane admission.</p>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "end" }}>
        <label>Name<input aria-label="Schedule name" required maxLength={100} value={name} onChange={event => setName(event.target.value)} /></label>
        <label>Every<input aria-label="Schedule interval" required maxLength={20} value={every} onChange={event => setEvery(event.target.value)} /></label>
        <label>Stored plane<select aria-label="Stored evidence plane" value={plane} onChange={event => setPlane(event.target.value)}>
          {PERSISTED_PLANES.map(value => <option key={value} value={value}>{value}</option>)}
        </select></label>
        <label>Scope label<input aria-label="Scope label" required maxLength={80} value={scope} onChange={event => setScope(event.target.value)} /></label>
        <label>Estate label<input aria-label="Estate label" required maxLength={120} value={estate} onChange={event => setEstate(event.target.value)} /></label>
        <button className="btn primary sm" type="submit" disabled={busy || !name.trim()}>
          {busy ? "Saving…" : "Enable projection cadence"}
        </button>
      </div>
    </form>}
    {error && <p role="alert">{error}</p>}
    {message && <p role="status">{message}</p>}
  </section>;
}
