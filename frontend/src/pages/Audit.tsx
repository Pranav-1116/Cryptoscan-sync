import { useMemo, useState } from "react";
import { Badge, Button, PageHead, Panel, Table } from "../components/ui.jsx";
import { useLive } from "../lib/useLive.js";
import type { AuditChainStatus, AuditEvent, AuditList } from "../lib/api.js";

/* The audit trail.
 *
 * The platform writes a hash-chained audit record and guide 112 proved it is
 * tamper-evident, but until now the console could only read it from inside the
 * evidence screen — /audit was a redirect. This page is that record's own
 * surface, and its job is to never overstate it:
 *
 *   - the chain verdict is shown beside the trail, and an unanswered verify call
 *     reads "CHAIN NOT VERIFIED", never a green badge. A badge that goes green
 *     because the request failed is worse than no badge;
 *   - a failed read of the trail says the trail could not be read, which is the
 *     opposite claim from "no events in this window";
 *   - filters are sent to the API as query parameters, so a filtered history is a
 *     smaller history rather than a client-side subset presented as the whole one.
 */

const PAGE_SIZE = 50;

interface Filters {
  actor: string;
  action: string;
}

const sameFilters = (a: Filters, b: Filters) => a.actor === b.actor && a.action === b.action;

function query(filters: Filters, page: number): string {
  const params = new URLSearchParams();
  params.set("page", String(page));
  params.set("page_size", String(PAGE_SIZE));
  if (filters.actor.trim()) params.set("actor", filters.actor.trim());
  if (filters.action.trim()) params.set("action", filters.action.trim());
  return `/api/v1/auth/audit?${params.toString()}`;
}

const text = (value: unknown): string =>
  typeof value === "string" && value.trim() ? value : "—";

function target(event: AuditEvent): string {
  const type = event.target_type ?? "";
  const id = event.target_id ?? "";
  if (!type && !id) return "—";
  if (type && id) return `${type} ${id}`;
  return type || id;
}

export default function Audit() {
  const [filters, setFilters] = useState<Filters>({ actor: "", action: "" });
  const [applied, setApplied] = useState<Filters>({ actor: "", action: "" });
  const [page, setPage] = useState(1);

  const list = useLive<AuditList>(query(applied, page), { events: [], page, page_size: PAGE_SIZE });
  const chain = useLive<AuditChainStatus>("/api/v1/auth/audit/verify", {
    status: "", checked: 0, entry_count: 0,
  });

  const events = useMemo(() => list.data.events ?? [], [list.data]);
  const filtered = Boolean(applied.actor || applied.action);
  const dirty = !sameFilters(filters, applied);

  const apply = () => {
    setPage(1);
    setApplied({ actor: filters.actor, action: filters.action });
  };
  const clear = () => {
    setFilters({ actor: "", action: "" });
    setPage(1);
    setApplied({ actor: "", action: "" });
  };

  return (
    <div className="page">
      <PageHead
        crumb="governance / audit"
        title="Audit trail"
        sub="Who did what, when — read from the platform's hash-chained record, not from a client log."
        right={<Badge tone={chain.data.status === "OK" ? "green" : "amber"}>{chain.data.status === "OK" ? "CHAIN VERIFIED" : "CHAIN NOT VERIFIED"}</Badge>}
      />

      <ChainVerdict state={chain} />

      <Panel
        title="Trail"
        sub={filtered
          ? "Filtered through the API: rows outside these filters are not read, so absence here is not absence in the trail."
          : "Every recorded action in this tenant, newest first."}
      >
        <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
          <input
            aria-label="Filter by actor"
            placeholder="actor"
            value={filters.actor}
            onChange={(e) => setFilters({ ...filters, actor: e.target.value })}
            onKeyDown={(e) => { if (e.key === "Enter") apply(); }}
          />
          <input
            aria-label="Filter by action"
            placeholder="action"
            value={filters.action}
            onChange={(e) => setFilters({ ...filters, action: e.target.value })}
            onKeyDown={(e) => { if (e.key === "Enter") apply(); }}
          />
          <Button onClick={apply} disabled={!dirty}>Apply filters</Button>
          {filtered && <Button onClick={clear}>Clear</Button>}
        </div>

        {list.error ? (
          <p role="alert">
            The audit trail could not be read ({list.error}). This is not an empty
            trail: the platform may hold events this screen cannot see right now.
          </p>
        ) : list.loading ? (
          <p role="status">Reading the audit trail…</p>
        ) : events.length === 0 ? (
          <p role="status">
            {filtered
              ? "No recorded action matches these filters. Clear them to read the whole trail."
              : "No action has been recorded yet — the trail starts with the first write."}
          </p>
        ) : (
          <>
            <Table
              head={["When", "Actor", "Action", "Target", "Outcome", "Source"]}
              rows={events.map((event) => [
                text(event.created_at),
                text(event.actor),
                text(event.action),
                target(event),
                <Badge tone={event.outcome === "SUCCESS" ? "green" : "amber"}>{text(event.outcome)}</Badge>,
                text(event.ip_address),
              ])}
            />
            <div className="row" style={{ gap: 8, marginTop: 10, alignItems: "center" }}>
              <Button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}>Newer</Button>
              <span role="status">page {page} · {events.length} row(s) this page</span>
              <Button onClick={() => setPage((p) => p + 1)} disabled={events.length < PAGE_SIZE}>Older</Button>
            </div>
          </>
        )}
      </Panel>
    </div>
  );
}

function ChainVerdict({ state }: { state: ReturnType<typeof useLive<AuditChainStatus>> }) {
  const { data, loading, error } = state;
  if (loading) {
    return (
      <Panel title="Chain verdict">
        <p role="status">Verifying the audit chain…</p>
      </Panel>
    );
  }
  // No answer, or an answer without a verdict, is not a pass. Say so.
  if (error || !data.status) {
    return (
      <Panel title="Chain verdict">
        <p role="alert">
          <strong>CHAIN NOT VERIFIED.</strong>{" "}
          {error
            ? `The verification endpoint did not answer (${error}), so the trail below has not been checked.`
            : "The verification endpoint answered without a verdict, so the trail below has not been checked."}
        </p>
      </Panel>
    );
  }
  if (data.status === "OK") {
    return (
      <Panel title="Chain verdict" sub="The server walked its own chain; these counts are its counts.">
        <p role="status">
          Verified: {data.checked} link(s) checked across {data.entry_count} recorded
          event(s), with no break{data.chain_head ? `; chain head ${data.chain_head}` : ""}.
        </p>
      </Panel>
    );
  }
  return (
    <Panel title="Chain verdict">
      <p role="alert">
        <strong>TAMPERED.</strong> The chain breaks at sequence{" "}
        {data.break_at_sequence ?? "unknown"}
        {data.reason ? `: ${data.reason}` : "."} Rows after that point cannot be
        trusted as recorded.
      </p>
    </Panel>
  );
}
