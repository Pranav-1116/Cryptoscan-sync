/* Reusable HUD primitives */

import React, { ReactNode } from "react";
import { IconClose, ICON_MD } from "./icons";
import { motion } from "framer-motion";
import { CountUp, DecryptText, DUR, EASE, useAutoAnimate, useMotionOK } from "../lib/motion";

export function Corners() {
  return (
    <>
      <span className="corner tl" />
      <span className="corner tr" />
      <span className="corner bl" />
      <span className="corner br" />
    </>
  );
}

export function Panel({ title, sub, children, frame = true, className = "", style }: {
  title?: ReactNode; sub?: string; children: ReactNode; frame?: boolean; className?: string; style?: React.CSSProperties;
}) {
  const ok = useMotionOK();
  const body = (
    <>
      {frame && <Corners />}
      {title && <h3>{title}</h3>}
      {sub && <p className="sub">{sub}</p>}
      {children}
    </>
  );
  // Every page is built from Panels, so animating here is what makes the
  // whole console settle in rather than snapping into place. Kept to an
  // 8px rise so a screen full of panels does not look like it is sliding.
  if (!ok) return <section className={`panel frame ${className}`} style={style}>{body}</section>;
  return (
    <motion.section
      className={`panel frame ${className}`}
      style={style}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: DUR.base, ease: EASE }}
    >
      {body}
    </motion.section>
  );
}

export function Stat({ label, value, delta, tone = "" }: { label: string; value: ReactNode; delta?: string; tone?: string }) {
  // A KPI that is a plain number counts up to it; anything else (a string,
  // a ratio, an element) renders as-is. Counting a figure the operator is
  // about to read is the one place motion carries information: it shows
  // the number is freshly measured rather than a static label.
  const numeric =
    typeof value === "number" && Number.isFinite(value)
      ? value
      : typeof value === "string" && /^\d{1,3}(,\d{3})*$|^\d+$/.test(value.trim())
        ? Number(value.replace(/,/g, ""))
        : null;
  return (
    <div className={`panel stat frame ${tone}`}>
      <Corners />
      <div className="label">{label}</div>
      <div className="value grad-text">
        {numeric === null ? value : <CountUp value={numeric} />}
      </div>
      {delta && <div className="delta">{delta}</div>}
    </div>
  );
}

export function Kpi({ k, v, tone }: { k: string; v: ReactNode; tone?: string }) {
  return (
    <div className="kpi">
      <span className="k">{k}</span>
      <span className="v" style={tone ? { color: `var(--${tone})` } : undefined}>{v}</span>
    </div>
  );
}

const BADGE_TONE: Record<string, string> = {
  // success / ok — green
  QUANTUM_SAFE: "green", PQC_READY: "green", ACTIVE: "green", ONLINE: "green", LIVE: "green",
  VALID: "green", HEALTHY: "green", LOW: "green", MATCHES: "green", COMPLIANT: "green",
  CONNECTED: "green", RUNNING: "green", COMPLETED: "green", YES: "green", APPROVED: "green",
  // critical — red
  QUANTUM_VULNERABLE: "red", EXPIRED: "red", CRITICAL: "red", VULNERABLE: "red",
  NON_COMPLIANT: "red", "NON-COMPLIANT": "red", STOPPED: "red", FAILED: "red", REVOKED: "red",
  MIGRATION_REQUIRED: "red",
  // high — orange
  HIGH: "orange",
  // warning / medium — amber
  EXPIRING: "amber", MEDIUM: "amber", SUSPECT: "amber", PARTIAL: "amber",
  PAUSED: "amber", NEW: "amber", SCHEDULED: "amber", WARNING: "amber",
  // informational / scanning — cyan·blue
  SCANNING: "cyan", INFO: "blue", MONITORING: "cyan", TRANSITIONING: "blue",
  HYBRID_READY: "violet", QUEUED: "blue",
  // unknown — slate
  UNKNOWN: "slate", PQC_UNKNOWN: "slate", OFFLINE: "slate",
};

/* variant → tone alias map (pages pass either `tone` or `variant`). */
const VARIANT_TO_TONE: Record<string, string> = {
  danger: "red", error: "red", critical: "red",
  success: "green", ok: "green",
  warning: "amber", warn: "amber",
  info: "cyan", primary: "cyan",
  neutral: "slate",
};

/* tone → tone alias map. `variant` has always been translated; `tone` was
 * passed straight into the class name, so `tone="warn"` (and "critical", "ok",
 * "bad", "muted") produced `class="badge warn"` — a class global.css does not
 * define, so the badge rendered with no colour at all and a warning looked like
 * a neutral label. Both spellings now resolve to a tone that exists. */
const TONE_ALIAS: Record<string, string> = {
  danger: "red", error: "red", critical: "red", bad: "red", fail: "red", failed: "red",
  success: "green", ok: "green", good: "green", pass: "green", live: "green", healthy: "green",
  warning: "amber", warn: "amber", medium: "amber",
  high: "orange",
  info: "cyan", primary: "cyan", accent: "cyan",
  neutral: "slate", muted: "slate", unknown: "slate", none: "slate",
};

export function Badge({ children, tone, variant }: { children: ReactNode; tone?: string; variant?: string }) {
  const named = tone || VARIANT_TO_TONE[variant || ""] || "";
  const resolved = TONE_ALIAS[String(named).toLowerCase()] ?? named;
  const t = resolved || BADGE_TONE[String(children).toString().toUpperCase()] || "";
  return (
    <span className={`badge ${t}`}>
      <span className="dot" />
      {children}
    </span>
  );
}

export function Kicker({ children }: { children: ReactNode }) {
  return <div className="kicker">{children}</div>;
}

export function Bar({ value, tone = "" }: { value: number; tone?: string }) {
  return (
    <div className="bar">
      <i className={tone} style={{ width: `${Math.min(100, Math.max(0, value * 100))}%` }} />
    </div>
  );
}

export function Ring({ pct, label, sub, tone = "cyan" }: { pct: number; label: ReactNode; sub: string; tone?: string }) {
  const r = 62;
  const c = 2 * Math.PI * r;
  const off = c * (1 - Math.min(1, Math.max(0, pct)));
  const colors: Record<string, string> = { cyan: "var(--accent)", green: "var(--green)", amber: "var(--amber)", orange: "var(--orange)", red: "var(--red)", violet: "var(--violet)", blue: "var(--accent)", slate: "var(--slate)", muted: "var(--slate)" };
  const col = colors[tone || "cyan"] || colors.cyan;
  return (
    <div className="ring">
      <svg width="150" height="150" viewBox="0 0 150 150">
        <circle cx="75" cy="75" r={r} fill="none" stroke="var(--line-strong)" strokeWidth="10" />
        <circle cx="75" cy="75" r={r} fill="none" stroke={col} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={off} />
      </svg>
      <div className="ring-label">
        <div>
          <b className="grad-text">{label}</b>
          <span>{sub}</span>
        </div>
      </div>
    </div>
  );
}

export function Table({ head, rows, total, clickable = false, selected = -1, onSelect }: {
  head: ReactNode[]; rows: ReactNode[][];
  /** How many rows exist before the caller capped the list.
   *
   * A table cut to twenty rows and shown without saying so reads as the whole
   * estate. Passing the true total lets the table state what it left out, which
   * is the difference between a bounded view and a misleading one. */
  total?: number;
  clickable?: boolean; selected?: number; onSelect?: (i: number) => void;
}) {
  const bodyRef = useAutoAnimate<HTMLTableSectionElement>();
  const interactive = clickable && onSelect;
  return (
    <div style={{ overflowX: "auto" }}>
      <table className={`tbl ${clickable ? "clickable" : ""}`}>
        <thead>
          <tr>{head.map((h, i) => <th key={i} scope="col">{h}</th>)}</tr>
        </thead>
        {/* auto-animate moves rows that are added, removed or reordered
            instead of letting the table jump under the cursor — which
            matters most on the live views, where rows arrive from SSE
            while the operator is reading. */}
        <tbody ref={bodyRef}>
          {rows.map((row, i) => (
            <tr
              key={i}
              className={selected === i ? "sel" : ""}
              onClick={interactive ? () => onSelect(i) : undefined}
              /* a clickable row is a control: keyboard users get the same
                 activation (Enter/Space) and an announced selection state —
                 audit 06's keyboard-navigation gap. */
              tabIndex={interactive ? 0 : undefined}
              role={interactive ? "button" : undefined}
              aria-selected={interactive ? (selected === i) : undefined}
              aria-label={interactive ? `Select row ${i + 1}` : undefined}
              onKeyDown={interactive ? (e: React.KeyboardEvent) => {
                if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSelect(i); }
              } : undefined}
            >
              {row.map((cell, j) => (
                <td key={j} className={typeof cell === "number" ? "num" : ""}>{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {typeof total === "number" && total > rows.length && (
        <div className="dim" role="status" style={{ fontSize: 12, padding: "6px 2px" }}>
          Showing the first {rows.length.toLocaleString()} of {total.toLocaleString()} rows — the
          table is capped so the page stays responsive; narrow the filters to see the rest.
        </div>
      )}
    </div>
  );
}

export function Feed({ items }: { items: { t: string; tag: string; text: string }[] }) {
  return (
    <div className="feed">
      {items.map((ev, i) => (
        <div className="ev" key={i}>
          <span className="t">{ev.t}</span>
          <span className="tag">{ev.tag}</span>
          <span className="txt">{ev.text}</span>
        </div>
      ))}
    </div>
  );
}

export function Tabs({ tabs, active, onChange }: { tabs: string[]; active: number; onChange: (i: number) => void }) {
  /* ARIA tabs pattern (audit 06): the container is a tablist, each button a
     tab; only the active tab is tab-reachable, and ArrowLeft/ArrowRight move
     between tabs (Home/End jump to the ends) with focus following the
     selection — the keyboard story a screen reader expects instead of N
     stops per tab bar. */
  const refs = React.useRef<(HTMLButtonElement | null)[]>([]);
  const move = (i: number, delta: number) => {
    const next = (i + delta + tabs.length) % tabs.length;
    onChange(next);
    refs.current[next]?.focus();
  };
  const jump = (i: number) => {
    onChange(i);
    refs.current[i]?.focus();
  };
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t, i) => (
        <button
          key={t}
          ref={(el) => { refs.current[i] = el; }}
          role="tab"
          className={i === active ? "active" : ""}
          aria-selected={i === active}
          tabIndex={i === active ? 0 : -1}
          onClick={() => onChange(i)}
          onKeyDown={(e) => {
            if (e.key === "ArrowRight") { e.preventDefault(); move(i, 1); }
            else if (e.key === "ArrowLeft") { e.preventDefault(); move(i, -1); }
            else if (e.key === "Home") { e.preventDefault(); jump(0); }
            else if (e.key === "End") { e.preventDefault(); jump(tabs.length - 1); }
          }}
        >{t}</button>
      ))}
    </div>
  );
}

export function Code({ children }: { children: ReactNode }) {
  return <pre className="code">{children}</pre>;
}

export function Drawer({ title, sub, onClose, children }: { title: ReactNode; sub?: ReactNode; onClose: () => void; children: ReactNode }) {
  return (
    <div className="drawer">
      <button className="close" onClick={onClose} aria-label="Close"><IconClose size={ICON_MD} /></button>
      <h2>{title}</h2>
      {sub && <div className="sub dim" style={{ marginBottom: 14, fontSize: 12.5 }}>{sub}</div>}
      {children}
    </div>
  );
}

export function PageHead({ crumb, title, sub, right }: { crumb: string; title: string; sub?: string; right?: ReactNode }) {
  return (
    <div className="topbar">
      <div>
        <div className="crumb">{crumb}</div>
        {/* Page titles resolve out of ciphertext on route change -- the
            console's one piece of thematic motion. See lib/motion.tsx. */}
        <h1><DecryptText text={title} className="mono-settle" /></h1>
        {sub && <div className="sub">{sub}</div>}
      </div>
      {right && <div className="row">{right}</div>}
    </div>
  );
}

/* Button — small button kit used by the interactive pages (MFA flows,
 * parsers, actions). Variants map onto the console design tokens. */
export function Button({
  children, onClick, disabled = false, variant = "default", type = "button", size = "md", style, title,
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: "default" | "primary" | "danger" | "ghost" | string;
  type?: "button" | "submit";
  size?: "sm" | "md" | "lg";
  style?: React.CSSProperties;
  title?: string;
}) {
  const colors: Record<string, { bg: string; border: string; fg: string }> = {
    primary: { bg: "color-mix(in srgb, var(--accent) 14%, transparent)", border: "var(--cyan)", fg: "var(--accent)" },
    danger: { bg: "color-mix(in srgb, var(--red) 12%, transparent)", border: "var(--red)", fg: "var(--red)" },
    default: { bg: "var(--bg-2)", border: "var(--line-strong)", fg: "var(--text)" },
    ghost: { bg: "transparent", border: "var(--line)", fg: "var(--dim)" },
  };
  const c = colors[variant] || colors.default;
  const padding = size === "sm" ? "5px 10px" : size === "lg" ? "10px 18px" : "7px 14px";
  const fontSize = size === "sm" ? 11.5 : size === "lg" ? 14 : 12.5;
  return (
    <button
      type={type}
      title={title}
      onClick={onClick}
      disabled={disabled}
      style={{
        display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 6,
        padding, borderRadius: "var(--r)", fontSize, fontWeight: 600,
        cursor: disabled ? "not-allowed" : "pointer", opacity: disabled ? 0.55 : 1,
        background: c.bg, border: `1px solid ${c.border}`, color: variant === "primary" ? c.fg : c.fg,
        transition: "filter 120ms ease", fontFamily: "inherit", ...style,
      }}
      onMouseEnter={(e) => { if (!disabled) (e.currentTarget as HTMLButtonElement).style.filter = "brightness(1.2)"; }}
      onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.filter = ""; }}
    >
      {children}
    </button>
  );
}

/* ProgressBar — 0..100 value. */
export function ProgressBar({ value, tone = "cyan", height = 8, label }: {
  value: number; tone?: string; height?: number; label?: ReactNode;
}) {
  const v = Math.min(100, Math.max(0, Number(value) || 0));
  const colors: Record<string, string> = { cyan: "var(--cyan)", green: "var(--green)", amber: "var(--amber)", red: "var(--red)" };
  return (
    <div>
      {label}
      <div
        style={{
          width: "100%", height, borderRadius: height / 2, background: "var(--bg-2)",
          border: "1px solid var(--line)", overflow: "hidden",
        }}
      >
        <div
          style={{
            width: `${v}%`, height: "100%", background: colors[tone] || colors.cyan,
            transition: "width 240ms ease",
          }}
        />
      </div>
    </div>
  );
}
