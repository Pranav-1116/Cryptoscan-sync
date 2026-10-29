/* Measurement primitives.
 *
 * These exist because the console's job on an operator screen is to show what
 * was measured, at a glance, and to say plainly when nothing was. Each one
 * renders only data it is given: a chart is never smoothed, extrapolated,
 * filled with placeholder history, or seeded with a demo series. When the
 * series is empty or too short to describe a shape, the component renders
 * `VizEmpty` — an explicit, labelled absence — rather than an empty axis that
 * invites the reader to assume zero.
 *
 * No gradients, no glows, no animations: a moving element competes with the
 * status colours, which are the only thing on these screens allowed to carry
 * urgency (see styles/global.css, --grad/--glow-* notes).
 */

import React, { ReactNode } from "react";
import { Link } from "react-router-dom";

/* The severity vocabulary the console's pages actually speak.
 *
 * Pages state a *state* ("ok", "warn", "critical"), a *severity* ("bad",
 * "suspicious"), or a colour. Only the colour names used to resolve; every
 * other word fell through to the accent, which painted a critical state in the
 * same blue as a neutral one — a status screen that cannot show red. Aliases
 * are resolved here, once, so both spellings reach the same token.
 *
 * No alias invents a state: "muted"/"unknown"/"none" mean an absence and map to
 * the slate absence token, never to a pass or a failure. */
const TONE: Record<string, string> = {
  "": "var(--accent)",
  accent: "var(--accent)",
  cyan: "var(--accent)",
  info: "var(--accent)",
  green: "var(--green)",
  amber: "var(--amber)",
  orange: "var(--orange)",
  red: "var(--red)",
  violet: "var(--violet)",
  slate: "var(--slate)",
};
const TONE_ALIAS: Record<string, string> = {
  ok: "green", good: "green", pass: "green", passed: "green", success: "green",
  live: "green", healthy: "green", verified: "green",
  warn: "amber", warning: "amber", medium: "amber", degraded: "amber",
  critical: "red", danger: "red", error: "red", fail: "red", failed: "red",
  bad: "red", incident: "red",
  high: "orange",
  muted: "slate", unknown: "slate", none: "slate", unmeasured: "slate",
};

/** Resolve a tone word to the CSS colour it stands for.
 *
 * Unknown words still render as the neutral accent so a typo cannot make a
 * value invisible — but every word the pages use is listed above. */
export function toneColor(tone = ""): string {
  const key = String(tone || "").trim().toLowerCase();
  return TONE[TONE_ALIAS[key] ?? key] ?? TONE[""];
}

/** A labelled absence. `note` says what would make the space fill. */
export function VizEmpty({
  title,
  note,
  height = 96,
}: {
  title: string;
  note?: string;
  height?: number;
}) {
  return (
    <div
      style={{
        minHeight: height,
        display: "flex",
        flexDirection: "column",
        justifyContent: "center",
        gap: 4,
        padding: "10px 12px",
        border: "1px dashed var(--line-strong)",
        borderRadius: "var(--r)",
        background: "var(--panel-2)",
      }}
    >
      <span className="mono" style={{ fontSize: 11, letterSpacing: "0.06em", color: "var(--dim)", textTransform: "uppercase" }}>
        {title}
      </span>
      {note && <span style={{ fontSize: 11.5, color: "var(--faint)", lineHeight: 1.4 }}>{note}</span>}
    </div>
  );
}

/** One measured number, with the unit and the window it was measured over. */
export function StateCell({
  label,
  value,
  note,
  tone = "",
  mono = true,
}: {
  label: string;
  value: ReactNode;
  note?: ReactNode;
  tone?: string;
  mono?: boolean;
}) {
  return (
    <div
      style={{
        padding: "8px 10px",
        border: "1px solid var(--line)",
        borderLeft: `2px solid ${tone ? toneColor(tone) : "var(--line-strong)"}`,
        borderRadius: "var(--r)",
        background: "var(--panel-2)",
        minWidth: 0,
      }}
    >
      <div className="mono" style={{ fontSize: 10, letterSpacing: "0.08em", color: "var(--faint)", textTransform: "uppercase" }}>
        {label}
      </div>
      <div
        style={{
          fontSize: 15,
          fontWeight: 600,
          marginTop: 2,
          fontFamily: mono ? "var(--mono)" : "var(--sans)",
          fontVariantNumeric: "tabular-nums",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          color: "var(--text)",
        }}
        title={typeof value === "string" ? value : undefined}
      >
        {value}
      </div>
      {note && <div style={{ fontSize: 10.5, color: "var(--faint)", marginTop: 2, lineHeight: 1.35 }}>{note}</div>}
    </div>
  );
}

/** Signed delta chip. Renders nothing for a zero delta rather than "+0". */
export function DeltaChip({ value }: { value: number }) {
  if (!value) return null;
  const up = value > 0;
  const color = up ? "var(--green)" : "var(--red)";
  return (
    <span
      className="mono"
      style={{
        fontSize: 10.5,
        fontWeight: 600,
        padding: "0 4px",
        borderRadius: 2,
        color,
        border: `1px solid ${color}`,
        fontVariantNumeric: "tabular-nums",
      }}
    >
      {up ? "+" : ""}
      {value}
    </span>
  );
}

/**
 * A sparkline of real samples, oldest → newest.
 *
 * `series` are the values actually read on this screen. Anything that is not a
 * finite number is a gap and is drawn as a gap: a missing read must not be
 * plotted as zero, because zero is a measurement and null is not.
 */
export function Sparkline({
  series,
  tone = "",
  height = 56,
  label,
  format = (n) => n.toLocaleString(),
  emptyNote,
}: {
  series: Array<number | null>;
  tone?: string;
  height?: number;
  label: string;
  format?: (n: number) => string;
  emptyNote?: string;
}) {
  const finite = series.filter((v): v is number => typeof v === "number" && Number.isFinite(v));
  if (finite.length < 2) {
    return <VizEmpty title={`${label} — no samples`} note={emptyNote ?? "The chart fills after two reads of this screen."} height={height} />;
  }
  const W = 100;
  const H = 100;
  const min = Math.min(...finite);
  const max = Math.max(...finite);
  const span = max - min || 1;
  const step = series.length > 1 ? W / (series.length - 1) : W;
  const y = (v: number) => H - ((v - min) / span) * H;
  const color = toneColor(tone);

  // Build contiguous runs so a null breaks the line instead of interpolating it.
  const runs: string[] = [];
  let current: string[] = [];
  series.forEach((v, i) => {
    if (typeof v === "number" && Number.isFinite(v)) {
      current.push(`${(i * step).toFixed(2)},${y(v).toFixed(2)}`);
    } else if (current.length) {
      runs.push(current.join(" "));
      current = [];
    }
  });
  if (current.length) runs.push(current.join(" "));

  const lastIndex = series.reduce<number>((acc, v, i) => (typeof v === "number" && Number.isFinite(v) ? i : acc), -1);
  const lastValue = lastIndex >= 0 ? (series[lastIndex] as number) : null;

  return (
    <figure style={{ margin: 0 }}>
      <div className="spread" style={{ marginBottom: 4 }}>
        <span className="mono" style={{ fontSize: 10, letterSpacing: "0.08em", color: "var(--faint)", textTransform: "uppercase" }}>
          {label}
        </span>
        <span className="mono" style={{ fontSize: 11, color: "var(--dim)", fontVariantNumeric: "tabular-nums" }}>
          {lastValue === null ? "—" : format(lastValue)} · {finite.length} sample(s)
        </span>
      </div>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="none"
        style={{ width: "100%", height, display: "block", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}
        role="img"
        aria-label={`${label}: ${finite.length} samples, minimum ${format(min)}, maximum ${format(max)}, latest ${lastValue === null ? "none" : format(lastValue)}`}
      >
        <line x1="0" y1={H - 0.5} x2={W} y2={H - 0.5} stroke="var(--line-strong)" strokeWidth="0.4" />
        {runs.map((points, i) => (
          <polyline key={i} points={points} fill="none" stroke={color} strokeWidth="1" vectorEffect="non-scaling-stroke" />
        ))}
      </svg>
      <figcaption className="mono" style={{ fontSize: 10, color: "var(--faint)", marginTop: 3, fontVariantNumeric: "tabular-nums" }}>
        min {format(min)} · max {format(max)} · {series.length - finite.length > 0 ? `${series.length - finite.length} unread sample(s)` : "no gaps"}
      </figcaption>
    </figure>
  );
}

export type BarRow = {
  key: string;
  label: string;
  value: number;
  tone?: string;
  to?: string;
  note?: string;
  delta?: number;
};

/**
 * Ranked horizontal bars. The bar length is `value / max(rows)` — a comparison
 * within what was read, never a percentage of a target nobody measured.
 */
export function HBars({ rows, unit = "", emptyTitle, emptyNote }: {
  rows: BarRow[];
  unit?: string;
  emptyTitle: string;
  emptyNote?: string;
}) {
  if (!rows.length) return <VizEmpty title={emptyTitle} note={emptyNote} />;
  const max = Math.max(...rows.map((r) => r.value), 0);
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
      {rows.map((r) => {
        const pct = max > 0 ? (r.value / max) * 100 : 0;
        const body = (
          <>
            <span style={{ fontSize: 11.5, color: r.value > 0 ? "var(--text)" : "var(--faint)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {r.label}
            </span>
            <span
              style={{ height: 8, background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 2, overflow: "hidden", display: "block" }}
            >
              <span
                style={{
                  display: "block",
                  width: `${Math.max(pct, r.value > 0 ? 2 : 0)}%`,
                  height: "100%",
                  background: toneColor(r.tone ?? ""),
                }}
              />
            </span>
            <span className="mono" style={{ fontSize: 11.5, textAlign: "right", fontVariantNumeric: "tabular-nums", color: r.value > 0 ? "var(--text)" : "var(--faint)" }}>
              {r.value.toLocaleString()}
              {unit}
            </span>
            <span style={{ width: 44, textAlign: "right" }}>
              <DeltaChip value={r.delta ?? 0} />
            </span>
          </>
        );
        const grid: React.CSSProperties = {
          display: "grid",
          gridTemplateColumns: "minmax(96px, 1.1fr) minmax(60px, 2fr) 56px 44px",
          gap: 8,
          alignItems: "center",
          textDecoration: "none",
          color: "inherit",
          padding: "2px 0",
        };
        return r.to ? (
          <Link key={r.key} to={r.to} style={grid} title={r.note ?? r.label}>
            {body}
          </Link>
        ) : (
          <div key={r.key} style={grid} title={r.note ?? r.label}>
            {body}
          </div>
        );
      })}
    </div>
  );
}

/** A single 100%-wide bar split into measured parts, with its own scale note. */
export function StackedBar({ segments, height = 10, note }: {
  segments: Array<{ key: string; label: string; value: number; tone?: string }>;
  height?: number;
  note?: string;
}) {
  const total = segments.reduce((sum, s) => sum + (Number.isFinite(s.value) ? Math.max(0, s.value) : 0), 0);
  if (!total) return <VizEmpty title="Nothing to compose" note={note} height={52} />;
  return (
    <div>
      <div style={{ display: "flex", height, borderRadius: 2, overflow: "hidden", border: "1px solid var(--line)" }}>
        {segments.map((s) => {
          if (!s.value) return null;
          return (
            <span
              key={s.key}
              title={`${s.label} ${s.value.toLocaleString()}`}
              style={{ width: `${(s.value / total) * 100}%`, background: toneColor(s.tone ?? "") }}
            />
          );
        })}
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginTop: 5 }}>
        {segments.filter((s) => s.value > 0).map((s) => (
          <span key={s.key} style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: 10.5, color: "var(--dim)" }}>
            <span style={{ width: 7, height: 7, borderRadius: 1, background: toneColor(s.tone ?? "") }} />
            {s.label}
            <span className="mono" style={{ color: "var(--text)", fontVariantNumeric: "tabular-nums" }}>{s.value.toLocaleString()}</span>
          </span>
        ))}
      </div>
      {note && <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 4 }}>{note}</div>}
    </div>
  );
}

/**
 * One column per real observation tick, coloured by severity of what that tick
 * contained. A gap in observation is a gap in the strip — it is not filled with
 * a neutral column that would read as "nothing happened".
 */
export function TickStrip({
  ticks,
  label,
  emptyNote,
}: {
  ticks: Array<{ ts: string; severity: "info" | "warn" | "critical" } | null>;
  label: string;
  emptyNote?: string;
}) {
  if (!ticks.length) return <VizEmpty title={`${label} — no ticks`} note={emptyNote} height={44} />;
  return (
    <div>
      <div className="spread" style={{ marginBottom: 4 }}>
        <span className="mono" style={{ fontSize: 10, letterSpacing: "0.08em", color: "var(--faint)", textTransform: "uppercase" }}>{label}</span>
        <span className="mono" style={{ fontSize: 10.5, color: "var(--dim)" }}>{ticks.length} tick(s)</span>
      </div>
      <div style={{ display: "flex", gap: 1, height: 26, alignItems: "flex-end" }}>
        {ticks.map((t, i) => (
          <span
            key={i}
            title={t ? `${t.ts} · ${t.severity}` : `${i} — not observed`}
            style={{
              flex: 1,
              height: t ? (t.severity === "critical" ? "100%" : t.severity === "warn" ? "66%" : "34%") : "100%",
              background: t ? (t.severity === "critical" ? "var(--red)" : t.severity === "warn" ? "var(--amber)" : "var(--green)") : "transparent",
              borderBottom: t ? "none" : "1px dashed var(--line-strong)",
              opacity: t ? 0.9 : 1,
            }}
          />
        ))}
      </div>
    </div>
  );
}

/** Small labelled percentage meter for a value the server actually reported. */
export function Meter({ value, label, tone = "", note }: { value: number; label: string; tone?: string; note?: string }) {
  const pct = Math.max(0, Math.min(100, value));
  return (
    <div>
      <div className="spread" style={{ marginBottom: 3 }}>
        <span style={{ fontSize: 11, color: "var(--dim)" }}>{label}</span>
        <span className="mono" style={{ fontSize: 11, fontVariantNumeric: "tabular-nums" }}>{pct}%</span>
      </div>
      <div style={{ height: 6, background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 2, overflow: "hidden" }}>
        <span style={{ display: "block", width: `${pct}%`, height: "100%", background: toneColor(tone) }} />
      </div>
      {note && <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 3 }}>{note}</div>}
    </div>
  );
}

/**
 * A `.kpi` row with an inline measure bar.
 *
 * Kept as a `.kpi` (same markup contract as the primitive in ui.tsx) because
 * several screens and tests locate a row by its label; the bar is the only
 * addition. `ratio` is a fraction of the largest value in the same group, not a
 * percentage of a target, and a null ratio renders no bar at all rather than a
 * zero-length one.
 */
export function KpiMeter({
  k,
  v,
  tone = "",
  ratio,
  note,
}: {
  k: string;
  v: ReactNode;
  tone?: string;
  ratio?: number | null;
  note?: string;
}) {
  const pct = typeof ratio === "number" && Number.isFinite(ratio) ? Math.max(0, Math.min(1, ratio)) * 100 : null;
  return (
    <div className="kpi" style={{ flexDirection: "column", alignItems: "stretch", gap: 5 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
        <span className="k">{k}</span>
        <span className="v" style={tone ? { color: `var(--${tone})` } : undefined}>{v}</span>
      </div>
      {pct !== null && (
        <span style={{ display: "block", height: 4, background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 1 }}>
          <span style={{ display: "block", width: `${pct}%`, height: "100%", background: toneColor(tone) }} />
        </span>
      )}
      {note && <span style={{ fontSize: 10, color: "var(--faint)", lineHeight: 1.35 }}>{note}</span>}
    </div>
  );
}

/**
 * A metric that was not measured, drawn as one.
 *
 * The alternative — an empty meter or a 0 — would leave the reader to guess
 * whether the instrument read zero or never ran. This says which.
 */
export function GapBar({ label, reason }: { label: string; reason: string }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
        <span className="mono" style={{ fontSize: 10.5, letterSpacing: "0.08em", color: "var(--faint)", textTransform: "uppercase" }}>{label}</span>
        <span className="mono" style={{ fontSize: 10.5, color: "var(--slate)" }}>not measured</span>
      </div>
      <span
        aria-hidden
        style={{
          display: "block",
          height: 6,
          borderRadius: 1,
          border: "1px dashed var(--line-strong)",
          backgroundImage:
            "repeating-linear-gradient(135deg, transparent 0 4px, color-mix(in srgb, var(--slate) 28%, transparent) 4px 6px)",
        }}
      />
      <span style={{ fontSize: 10, color: "var(--faint)", lineHeight: 1.35 }}>{reason}</span>
    </div>
  );
}
