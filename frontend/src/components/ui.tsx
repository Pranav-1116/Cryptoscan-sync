/* Reusable HUD primitives */

import React, { ReactNode } from "react";

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
  title?: string; sub?: string; children: ReactNode; frame?: boolean; className?: string; style?: React.CSSProperties;
}) {
  return (
    <section className={`panel frame ${className}`} style={style}>
      {frame && <Corners />}
      {title && <h3>{title}</h3>}
      {sub && <p className="sub">{sub}</p>}
      {children}
    </section>
  );
}

export function Stat({ label, value, delta, tone = "" }: { label: string; value: ReactNode; delta?: string; tone?: string }) {
  return (
    <div className={`panel stat frame ${tone}`}>
      <Corners />
      <div className="label">{label}</div>
      <div className="value grad-text">{value}</div>
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
  QUANTUM_SAFE: "green", PQC_READY: "green", ACTIVE: "green", ONLINE: "green",
  VALID: "green", HEALTHY: "green", LOW: "green", MATCHES: "green", COMPLIANT: "green",
  CONNECTED: "green", RUNNING: "green", COMPLETED: "green", YES: "green",
  QUANTUM_VULNERABLE: "red", EXPIRED: "red", CRITICAL: "red", HIGH: "red",
  NON_COMPLIANT: "red", "NON-COMPLIANT": "red", STOPPED: "red",
  EXPIRING: "amber", MEDIUM: "amber", SUSPECT: "amber", PARTIAL: "amber",
  PAUSED: "amber", UNKNOWN: "amber", PQC_UNKNOWN: "amber", NEW: "amber", SCHEDULED: "amber",
  HYBRID_READY: "violet", MIGRATION_REQUIRED: "red",
};

export function Badge({ children, tone }: { children: ReactNode; tone?: string }) {
  const t = tone || BADGE_TONE[String(children).toString().toUpperCase()] || "";
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
  const colors: Record<string, string> = { cyan: "#22d3ee", green: "#34d399", amber: "#fbbf24", red: "#f87171", violet: "#8b5cf6" };
  const col = colors[tone || "cyan"] || colors.cyan;
  return (
    <div className="ring">
      <svg width="150" height="150" viewBox="0 0 150 150">
        <circle cx="75" cy="75" r={r} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="10" />
        <circle cx="75" cy="75" r={r} fill="none" stroke={col} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={off} style={{ filter: `drop-shadow(0 0 8px ${col})` }} />
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

export function Table({ head, rows, clickable = false, selected = -1, onSelect }: {
  head: ReactNode[]; rows: ReactNode[][]; clickable?: boolean; selected?: number; onSelect?: (i: number) => void;
}) {
  return (
    <div style={{ overflowX: "auto" }}>
      <table className={`tbl ${clickable ? "clickable" : ""}`}>
        <thead>
          <tr>{head.map((h, i) => <th key={i}>{h}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className={selected === i ? "sel" : ""} onClick={clickable && onSelect ? () => onSelect(i) : undefined}>
              {row.map((cell, j) => (
                <td key={j} className={typeof cell === "number" ? "num" : ""}>{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
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
  return (
    <div className="tabs">
      {tabs.map((t, i) => (
        <button key={t} className={i === active ? "active" : ""} onClick={() => onChange(i)}>{t}</button>
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
      <button className="close" onClick={onClose}>✕</button>
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
        <h1>{title}</h1>
        {sub && <div className="sub">{sub}</div>}
      </div>
      {right && <div className="row">{right}</div>}
    </div>
  );
}
