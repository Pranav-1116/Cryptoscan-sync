import { useNavigate } from "react-router-dom";
/* Global search & command palette — Ctrl+K / Cmd+K
 * ChatGPT-style usability + enterprise cybersecurity command palette.
 * Searches assets, services, certificates, dependencies, policies, evidence, and runnable actions. */

import React, { useEffect, useRef, useState } from "react";
import { apiAlgorithmCatalog } from "../lib/api.js";

interface Item {
  name: string;
  to: string;
  meta: string;
  category?: string;
  isAction?: boolean;
}

interface Group {
  label: string;
  icon: string;
  items: Item[];
}

const QUICK_ACTIONS: Item[] = [
  { name: "Start estate scan", to: "#/scanners", meta: "Action", isAction: true, category: "Actions" },
  { name: "View CBOM (Cryptographic Bill of Materials)", to: "#/cbom", meta: "Action", isAction: true, category: "Actions" },
  { name: "Export CBOM", to: "#/cbom", meta: "Action", isAction: true, category: "Actions" },
  { name: "View PQC readiness dashboard", to: "#/pqc", meta: "Action", isAction: true, category: "Actions" },
  { name: "Find RSA-2048 assets", to: "#/assets", meta: "Filter", isAction: true, category: "Actions" },
  { name: "Show certificate expiry", to: "#/certificates", meta: "Action", isAction: true, category: "Actions" },
  { name: "Open dependency graph", to: "#/graph", meta: "Action", isAction: true, category: "Actions" },
  { name: "Generate compliance report", to: "#/compliance", meta: "Action", isAction: true, category: "Actions" },
  { name: "Inspect evidence chain WORM", to: "#/evidence", meta: "Action", isAction: true, category: "Actions" },
  { name: "Simulate PQC migration (CDT)", to: "#/whatif", meta: "Action", isAction: true, category: "Actions" },
];

export default function SearchOverlay({ onClose }: { onClose: () => void }) {
  const [q, setQ] = useState("");
  const [groups, setGroups] = useState<Group[]>([]);
  const [searching, setSearching] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  useEffect(() => {
    const term = q.trim().toLowerCase();
    if (!term) {
      setGroups([
        {
          label: "Suggested Quick Actions",
          icon: "⚡",
          items: QUICK_ACTIONS.slice(0, 6)
        }
      ]);
      return;
    }

    let cancelled = false;
    setSearching(true);

    const matchingActions = QUICK_ACTIONS.filter(a =>
      a.name.toLowerCase().includes(term) || a.meta.toLowerCase().includes(term)
    );

    const t = setTimeout(() => {
      apiAlgorithmCatalog({ q: term }).then((res) => {
        if (cancelled) return;
        const rows = (res.data?.algorithms ?? []) as any[];
        const algoItems: Item[] = rows.slice(0, 6).map((a) => ({
          name: `${a.name ?? a.algorithm ?? a.id}${a.family ? ` · ${a.family}` : ""}`,
          to: "#/catalog",
          meta: a.status ?? a.quantum_status ?? "Active",
          category: "Algorithms"
        }));

        const newGroups: Group[] = [];
        if (matchingActions.length > 0) {
          newGroups.push({ label: "Actions & Commands", icon: "⚡", items: matchingActions });
        }
        if (algoItems.length > 0) {
          newGroups.push({ label: "Cryptographic Assets & Algorithms", icon: "🔐", items: algoItems });
        }

        // Add domain category matches
        const mockDomainMatches: Item[] = [];
        if ("certificates".includes(term) || "tls".includes(term) || "expiring".includes(term)) {
          mockDomainMatches.push({ name: "TLS 1.2 / 1.3 Active Certificates", to: "#/certificates", meta: "1,823 verified", category: "Certificates" });
        }
        if ("rsa".includes(term) || "assets".includes(term) || "pqc".includes(term)) {
          mockDomainMatches.push({ name: "PQC Vulnerable RSA-2048 Core Banking Keys", to: "#/assets", meta: "PQC Migration Required", category: "Assets" });
        }
        if ("evidence".includes(term) || "worm".includes(term) || "audit".includes(term)) {
          mockDomainMatches.push({ name: "WORM Tamper-Evident S3 Manifests", to: "#/evidence", meta: "Verified SHA-256", category: "Evidence" });
        }
        if (mockDomainMatches.length > 0) {
          newGroups.push({ label: "Estate Discovery", icon: "⌕", items: mockDomainMatches });
        }

        setGroups(newGroups);
        setSearching(false);
      }).catch(() => {
        if (!cancelled) {
          setGroups(matchingActions.length > 0 ? [{ label: "Actions & Commands", icon: "⚡", items: matchingActions }] : []);
          setSearching(false);
        }
      });
    }, 150);

    return () => { cancelled = true; clearTimeout(t); };
  }, [q]);

  const flatItems = groups.flatMap(g => g.items);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIndex(prev => (prev + 1) % (flatItems.length || 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIndex(prev => (prev - 1 + flatItems.length) % (flatItems.length || 1));
    } else if (e.key === "Enter" && flatItems[selectedIndex]) {
      e.preventDefault();
      navigate(flatItems[selectedIndex].to);
      onClose();
    }
  };

  return (
    <div className="searchov" onClick={onClose}>
      <div className="box" onClick={(e) => e.stopPropagation()} style={{ maxWidth: "720px" }}>
        <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
          <span style={{ position: "absolute", left: "20px", color: "var(--cyan)", fontSize: "18px" }}>⌘</span>
          <input
            ref={inputRef}
            placeholder="Type a command or search: RSA, TLS 1.0, expiring certificates, CBOM..."
            value={q}
            onChange={(e) => { setQ(e.target.value); setSelectedIndex(0); }}
            onKeyDown={handleKeyDown}
            style={{ paddingLeft: "48px" }}
          />
        </div>
        {q.trim() && !searching && groups.length === 0 ? (
          <div className="empty">no matches for “{q}” — try searching for RSA, TLS, or an action</div>
        ) : searching ? (
          <div className="empty">searching cryptographic estate & catalog…</div>
        ) : (
          <div className="groups" style={{ display: "block" }}>
            {groups.map((g) => (
              <div className="group" key={g.label} style={{ borderBottom: "1px solid var(--line)" }}>
                <div className="glabel">{g.icon} {g.label}</div>
                {g.items.map((it) => {
                  const globalIdx = flatItems.indexOf(it);
                  const isSelected = globalIdx === selectedIndex;
                  return (
                    <a
                      className="gitem"
                      key={`${it.name}-${it.to}`}
                      href={it.to}
                      onClick={(e) => { e.preventDefault(); navigate(it.to); onClose(); }}
                      style={{
                        background: isSelected ? "rgba(0, 212, 255, 0.12)" : undefined,
                        borderLeft: isSelected ? "2px solid var(--cyan)" : "2px solid transparent",
                        padding: "8px 12px",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between"
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                        <span style={{ color: it.isAction ? "var(--cyan)" : "var(--text)", fontSize: "13.5px" }}>
                          {it.isAction ? "> " : ""}{it.name}
                        </span>
                      </div>
                      <span className="meta" style={{ fontSize: "11px", background: "var(--panel-2)", padding: "2px 6px", borderRadius: "4px" }}>
                        {it.meta}
                      </span>
                    </a>
                  );
                })}
              </div>
            ))}
          </div>
        )}
        <div className="hint" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span>Navigate with <kbd style={{ background: "var(--panel-2)", padding: "1px 5px", borderRadius: "3px" }}>↑</kbd> <kbd style={{ background: "var(--panel-2)", padding: "1px 5px", borderRadius: "3px" }}>↓</kbd> · Select with <kbd style={{ background: "var(--panel-2)", padding: "1px 5px", borderRadius: "3px" }}>Enter</kbd></span>
          <span>esc to close</span>
        </div>
      </div>
    </div>
  );
}
