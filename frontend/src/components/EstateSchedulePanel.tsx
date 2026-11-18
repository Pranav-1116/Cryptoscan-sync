import React, { useState } from "react";
import { usePrivateScopeCurrent } from "./PrivateScope";
import { usePollingApi } from "../lib/apiUi";
import { apiEstateCreateSchedule, apiEstateSchedules, getRoles } from "../lib/api";
import { Badge } from "./ui";
import { VizEmpty } from "./viz";

const PERSISTED_PLANES = ["STATIC", "HARDWARE", "NETWORK", "RUNTIME", "PKI", "VENDOR"];

/* Approval of a cadence authorizes a *reprojection* of evidence already stored.
 * It never authorizes a collector, so the caveat is stated once, in the
 * subtitle, instead of a paragraph above the controls. */
export default function EstateSchedulePanel() {
  const current = usePrivateScopeCurrent();
  const schedules = usePollingApi(apiEstateSchedules, 30000, [], { channels: ["estate"] });
  const canManage = getRoles().some((role) => role === "superadmin" || role === "ciso");
  const [name, setName] = useState("");
  const [every, setEvery] = useState("6h");
  const [plane, setPlane] = useState("STATIC");
  const [scope, setScope] = useState("local");
  const [estate, setEstate] = useState("default");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const rows =
    schedules.source === "live" && Array.isArray(schedules.data?.schedules) ? schedules.data.schedules : null;

  const create = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy || !current()) return;
    setBusy(true);
    setMessage("");
    setError("");
    try {
      const result = await apiEstateCreateSchedule({
        name: name.trim(),
        every: every.trim(),
        planes: [plane],
        enabled: true,
        scope: scope.trim(),
        estate: estate.trim(),
      });
      if (!current()) return;
      if (
        result.source !== "live" ||
        result.ok !== true ||
        !result.data?.id ||
        result.data.name !== name.trim() ||
        result.data.enabled !== true ||
        !result.data.planes?.includes(plane)
      ) {
        setError(`Schedule outcome unconfirmed (${result.error || "invalid receipt"}); inspect the retained list before retrying.`);
        return;
      }
      setMessage(
        `Projection schedule ${result.data.name} saved · ID ${result.data.id} · next due ${result.data.next_run_at}. No new collection was authorized.`,
      );
      setName("");
      await schedules.run();
    } catch (cause) {
      if (current())
        setError(
          `Schedule outcome unconfirmed (${cause instanceof Error ? cause.message : String(cause)}); inspect the retained list before retrying.`,
        );
    } finally {
      if (current()) setBusy(false);
    }
  };

  const enabled = rows?.filter((row) => row.enabled).length ?? 0;

  return (
    <section
      className="panel"
      aria-label="Evidence projection schedules"
      style={{ padding: "10px 12px", marginBottom: 12 }}
    >
      <div className="spread" style={{ alignItems: "baseline" }}>
        <h3 style={{ margin: 0, fontSize: 13, fontWeight: 600 }}>Evidence projection schedules</h3>
        <span className="mono" style={{ fontSize: 10.5, color: "var(--faint)" }}>
          {rows === null ? "list not read" : `${rows.length} schedule(s) · ${enabled} enabled`}
        </span>
      </div>
      <p className="sub" style={{ margin: "3px 0 10px" }}>
        <span title={"A cadence re-reads retained evidence; it does not scan source, probe endpoints, or contact cloud/HSM providers. Register and approve collection separately. A schedule with no stored observations proves no coverage."}>{"A cadence re-reads retained evidence"}</span>
      </p>

      {rows === null ? (
        <p role="alert" style={{ margin: 0, fontSize: 12, color: "var(--amber)" }}>
          Schedule list unavailable or incomplete; no absence inferred.
        </p>
      ) : rows.length === 0 ? (
        <VizEmpty title="No projection cadence registered" note="No schedules in this estate. Nothing is reprojected." height={56} />
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table className="tbl" style={{ width: "100%", fontSize: 11.5 }}>
            <thead>
              <tr>
                <th style={{ textAlign: "left" }}>Name</th>
                <th style={{ textAlign: "left" }}>State</th>
                <th style={{ textAlign: "left" }}>Planes</th>
                <th style={{ textAlign: "left" }}>Next due</th>
                <th style={{ textAlign: "left" }}>Last verdict</th>
                <th style={{ textAlign: "left" }}>Coverage</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id}>
                  <td>{row.name}</td>
                  <td>
                    <Badge tone={row.enabled ? "green" : "slate"}>{row.enabled ? "enabled" : "paused"}</Badge>
                  </td>
                  <td className="mono">{row.planes?.join(", ") || "unqualified legacy scope"}</td>
                  <td className="mono">{row.next_run_at || "—"}</td>
                  <td>{row.last_run?.verdict || "NOT_RUN"}</td>
                  <td>{row.last_run?.coverage_state || "UNKNOWN"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {canManage && (
        <form onSubmit={(event) => void create(event)} style={{ marginTop: 12, paddingTop: 10, borderTop: "1px solid var(--line)" }}>
          <div className="mono" style={{ fontSize: 10, letterSpacing: "0.08em", color: "var(--faint)", textTransform: "uppercase", marginBottom: 6 }}>
            Register a cadence
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: 8, alignItems: "end" }}>
            <label style={{ display: "block", fontSize: 11, color: "var(--dim)" }}>
              Name
              <input className="inp" style={{ width: "100%", marginTop: 3 }} aria-label="Schedule name" required maxLength={100} value={name} onChange={(event) => setName(event.target.value)} />
            </label>
            <label style={{ display: "block", fontSize: 11, color: "var(--dim)" }}>
              Every
              <input className="inp" style={{ width: "100%", marginTop: 3 }} aria-label="Schedule interval" required maxLength={20} value={every} onChange={(event) => setEvery(event.target.value)} />
            </label>
            <label style={{ display: "block", fontSize: 11, color: "var(--dim)" }}>
              Stored plane
              <select className="inp" style={{ width: "100%", marginTop: 3 }} aria-label="Stored evidence plane" value={plane} onChange={(event) => setPlane(event.target.value)}>
                {PERSISTED_PLANES.map((value) => (
                  <option key={value} value={value}>{value}</option>
                ))}
              </select>
            </label>
            <label style={{ display: "block", fontSize: 11, color: "var(--dim)" }}>
              Scope label
              <input className="inp" style={{ width: "100%", marginTop: 3 }} aria-label="Scope label" required maxLength={80} value={scope} onChange={(event) => setScope(event.target.value)} />
            </label>
            <label style={{ display: "block", fontSize: 11, color: "var(--dim)" }}>
              Estate label
              <input className="inp" style={{ width: "100%", marginTop: 3 }} aria-label="Estate label" required maxLength={120} value={estate} onChange={(event) => setEstate(event.target.value)} />
            </label>
            <button className="btn btn-primary" type="submit" disabled={busy || !name.trim()} style={{ height: 30 }}>
              {busy ? "Saving…" : "Enable projection cadence"}
            </button>
          </div>
          <p style={{ fontSize: 10.5, color: "var(--faint)", margin: "6px 0 0" }}>
            The server rechecks durable human authority and plane admission before storing a cadence.
          </p>
        </form>
      )}

      {error && (
        <p role="alert" style={{ margin: "8px 0 0", fontSize: 11.5, color: "var(--red)" }}>
          {error}
        </p>
      )}
      {message && (
        <p role="status" style={{ margin: "8px 0 0", fontSize: 11.5, color: "var(--green)" }}>
          {message}
        </p>
      )}
    </section>
  );
}
