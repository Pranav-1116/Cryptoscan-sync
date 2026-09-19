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
  const colors: Record<string, string> = { cyan: "#00d4ff", green: "#22c55e", amber: "#f59e0b", orange: "#f97316", red: "#ef4444", violet: "#8b7cf6", blue: "#3b82f6" };
  const col = colors[tone || "cyan"] || colors.cyan;
  return (
    <div className="ring">
      <svg width="150" height="150" viewBox="0 0 150 150">
        <circle cx="75" cy="75" r={r} fill="none" stroke="#26324b" strokeWidth="10" />
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

export function Row({ children, style, className = "" }: { children: ReactNode; style?: React.CSSProperties; className?: string }) {
  return (
    <div className={`grid-row ${className}`} style={{ display: "flex", flexWrap: "wrap", gap: "16px", ...style }}>
      {children}
    </div>
  );
}

export function Col({ children, span, style, className = "" }: { children: ReactNode; span?: number; style?: React.CSSProperties; className?: string }) {
  const flexStyle = span ? { flex: `0 0 calc(${(span / 12) * 100}% - 16px)`, minWidth: "260px" } : { flex: "1 1 0%", minWidth: "260px" };
  return (
    <div className={`grid-col ${className}`} style={{ ...flexStyle, ...style }}>
      {children}
    </div>
  );
}


/* ── Modern Premium UI Components (ChatGPT-style Usability + Enterprise Security) ── */

export function Button({
  children,
  variant = "secondary",
  size = "md",
  icon,
  disabled,
  onClick,
  style,
  className = "",
  type = "button"
}: {
  children: React.ReactNode;
  variant?: "primary" | "secondary" | "ghost" | "danger" | "outline";
  size?: "sm" | "md" | "lg";
  icon?: React.ReactNode;
  disabled?: boolean;
  onClick?: (e: React.MouseEvent) => void;
  style?: React.CSSProperties;
  className?: string;
  type?: "button" | "submit" | "reset";
}) {
  const vClass = variant === "primary" ? "btn primary" : variant === "ghost" ? "btn ghost" : variant === "danger" ? "btn danger" : variant === "outline" ? "btn outline" : "btn";
  const sClass = size === "sm" ? "sm" : size === "lg" ? "lg" : "";
  return (
    <button
      type={type}
      disabled={disabled}
      onClick={onClick}
      style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", gap: "8px", ...style }}
      className={`${vClass} ${sClass} ${className}`}
    >
      {icon && <span className="btn-icon">{icon}</span>}
      {children}
    </button>
  );
}

export function Input({
  value,
  onChange,
  placeholder,
  label,
  type = "text",
  error,
  icon,
  disabled,
  style,
  className = ""
}: {
  value?: string | number;
  onChange?: (e: React.ChangeEvent<HTMLInputElement>) => void;
  placeholder?: string;
  label?: string;
  type?: string;
  error?: string;
  icon?: React.ReactNode;
  disabled?: boolean;
  style?: React.CSSProperties;
  className?: string;
}) {
  return (
    <div className="input-group" style={{ display: "flex", flexDirection: "column", gap: "6px", width: "100%", ...style }}>
      {label && <label style={{ fontSize: "12px", fontWeight: 600, color: "var(--dim)" }}>{label}</label>}
      <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
        {icon && <span style={{ position: "absolute", left: "12px", color: "var(--faint)", pointerEvents: "none" }}>{icon}</span>}
        <input
          type={type}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          disabled={disabled}
          className={`inp ${className}`}
          style={{ paddingLeft: icon ? "36px" : "12px", width: "100%" }}
        />
      </div>
      {error && <span style={{ fontSize: "11px", color: "var(--red)" }}>{error}</span>}
    </div>
  );
}

export function Card({
  title,
  sub,
  children,
  action,
  className = "",
  style
}: {
  title?: React.ReactNode;
  sub?: React.ReactNode;
  children: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
}) {
  return (
    <div className={`panel ${className}`} style={{ padding: "20px", ...style }}>
      {(title || action) && (
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: sub ? "4px" : "16px" }}>
          {title && <h3 style={{ margin: 0, fontSize: "15px", fontWeight: 600, color: "var(--text)" }}>{title}</h3>}
          {action && <div>{action}</div>}
        </div>
      )}
      {sub && <p style={{ margin: "0 0 16px", fontSize: "12.5px", color: "var(--dim)" }}>{sub}</p>}
      {children}
    </div>
  );
}

export function Skeleton({ height = 24, width = "100%", borderRadius = 6, style }: { height?: number | string; width?: number | string; borderRadius?: number; style?: React.CSSProperties }) {
  return (
    <div
      className="skeleton"
      style={{
        height,
        width,
        borderRadius,
        background: "var(--panel-2)",
        animation: "skeleton-pulse 1.5s ease-in-out infinite",
        ...style
      }}
    />
  );
}

export function EmptyState({
  title = "No cryptographic assets found",
  description = "Run a discovery scan to begin building your cryptographic inventory.",
  actionLabel = "Start Scan",
  onAction,
  icon = "⌕"
}: {
  title?: string;
  description?: string;
  actionLabel?: string;
  onAction?: () => void;
  icon?: React.ReactNode;
}) {
  return (
    <div className="empty-state" style={{ padding: "48px 24px", textAlign: "center", background: "var(--panel)", borderRadius: "10px", border: "1px dashed var(--line)" }}>
      <div style={{ fontSize: "32px", color: "var(--cyan)", marginBottom: "12px" }}>{icon}</div>
      <h3 style={{ margin: "0 0 8px", fontSize: "16px", fontWeight: 600, color: "var(--text)" }}>{title}</h3>
      <p style={{ margin: "0 auto 20px", maxWidth: "420px", fontSize: "13px", color: "var(--dim)" }}>{description}</p>
      {onAction && (
        <Button variant="primary" onClick={onAction}>
          {actionLabel}
        </Button>
      )}
    </div>
  );
}

export function ErrorState({
  title = "We couldn't complete the scan",
  description = "The target did not respond within the configured timeout.",
  onRetry,
  details
}: {
  title?: string;
  description?: string;
  onRetry?: () => void;
  details?: string;
}) {
  const [showDetails, setShowDetails] = React.useState(false);
  return (
    <div className="error-state" style={{ padding: "24px", background: "rgba(239,68,68,0.06)", border: "1px solid rgba(239,68,68,0.25)", borderRadius: "10px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "10px", color: "var(--red)", marginBottom: "8px" }}>
        <span style={{ fontSize: "18px" }}>⚠</span>
        <h3 style={{ margin: 0, fontSize: "15px", fontWeight: 600 }}>{title}</h3>
      </div>
      <p style={{ margin: "0 0 16px", fontSize: "13px", color: "var(--dim)" }}>{description}</p>
      <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
        {onRetry && <Button variant="secondary" size="sm" onClick={onRetry}>Retry</Button>}
        {details && (
          <button className="btn sm ghost" onClick={() => setShowDetails(!showDetails)}>
            {showDetails ? "Hide Details" : "View Details"}
          </button>
        )}
      </div>
      {showDetails && details && (
        <pre style={{ marginTop: "12px", padding: "12px", background: "var(--bg)", borderRadius: "6px", fontSize: "11.5px", color: "var(--dim)", overflowX: "auto" }}>
          {details}
        </pre>
      )}
    </div>
  );
}

export function ProgressBar({ value, max = 100, label, tone = "cyan" }: { value: number; max?: number; label?: string; tone?: string }) {
  const pct = Math.min(100, Math.max(0, (value / max) * 100));
  return (
    <div style={{ width: "100%" }}>
      {label && (
        <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px", color: "var(--dim)", marginBottom: "6px" }}>
          <span>{label}</span>
          <span style={{ fontFamily: "var(--mono)", fontWeight: 600 }}>{Math.round(pct)}%</span>
        </div>
      )}
      <div className="bar thick">
        <i className={tone} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

export function Modal({ isOpen, onClose, title, children }: { isOpen: boolean; onClose: () => void; title: React.ReactNode; children: React.ReactNode }) {
  if (!isOpen) return null;
  return (
    <div className="searchov" onClick={onClose} style={{ zIndex: 1000 }}>
      <div className="box" onClick={(e) => e.stopPropagation()} style={{ maxWidth: "600px", width: "90%", padding: "24px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px", borderBottom: "1px solid var(--line)", paddingBottom: "12px" }}>
          <h2 style={{ margin: 0, fontSize: "17px", fontWeight: 600 }}>{title}</h2>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "var(--dim)", cursor: "pointer", fontSize: "18px" }}>✕</button>
        </div>
        {children}
      </div>
    </div>
  );
}
