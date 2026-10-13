/* Global search — one box across the entire environment (spec §4).
 * Queries the LIVE algorithm catalog (the deterministic reference KB); with
 * an empty estate that is still real reference data. No local/demo index. */

import React, { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { apiAlgorithmCatalog } from "../lib/api.js";
import { IconCrypto, ICON_SM, type Icon } from "./icons";

interface Item { name: string; to: string; meta: string }
interface Group { label: string; icon: Icon; items: Item[] }

export default function SearchOverlay({ onClose }: { onClose: () => void }) {
  const [q, setQ] = useState("");
  const [groups, setGroups] = useState<Group[]>([]);
  const [searching, setSearching] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const resultsTo = `/search-results?q=${encodeURIComponent(q.trim())}`;
  const openResults = () => {
    if (!q.trim()) return;
    navigate(resultsTo);
    onClose();
  };

  useEffect(() => {
    inputRef.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  useEffect(() => {
    const term = q.trim();
    if (!term) { setGroups([]); return; }
    let cancelled = false;
    setSearching(true);
    const t = setTimeout(() => {
      apiAlgorithmCatalog({ q: term }).then((res) => {
        if (cancelled) return;
        const rows = (res.data?.algorithms ?? []) as any[];
        const items: Item[] = rows.slice(0, 6).map((a) => ({
          name: `${a.name ?? a.algorithm ?? a.id}${a.family ? ` · ${a.family}` : ""}`,
          to: "/catalog",
          meta: a.status ?? a.quantum_status ?? "",
        }));
        setGroups(items.length ? [{ label: "Algorithms", icon: IconCrypto, items }] : []);
        setSearching(false);
      }).catch(() => { if (!cancelled) { setGroups([]); setSearching(false); } });
    }, 200);
    return () => { cancelled = true; clearTimeout(t); };
  }, [q]);

  const total = groups.reduce((n, g) => n + g.items.length, 0);

  return (
    <div className="searchov" onClick={onClose}>
      <div className="box" onClick={(e) => e.stopPropagation()}>
        <input
          ref={inputRef}
          placeholder="Search the algorithm catalog (RSA, AES, ML-KEM)…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") openResults(); }}
          aria-label="Search the algorithm catalog"
        />
        {q.trim() && !searching && total === 0 ? (
          <div className="empty">no algorithm-catalog matches for “{q}” — full search also covers protocols, hardware and scan findings</div>
        ) : searching ? (
          <div className="empty">searching live catalog…</div>
        ) : (
          <div className="groups">
            {groups.map((g) => (
              <div className="group" key={g.label}>
                <div className="glabel ico-row"><g.icon className="ico" size={ICON_SM} /><span>{g.label} · {g.items.length}</span></div>
                {g.items.map((it, i) => (
                  <Link className="gitem" key={`${it.name}-${i}`} to={it.to} onClick={onClose}>
                    <span>{it.name}</span>
                    <span className="meta">{it.meta}</span>
                  </Link>
                ))}
              </div>
            ))}
          </div>
        )}
        {q.trim() && <Link to={resultsTo} onClick={onClose} className="gitem">View all results for “{q.trim()}” →</Link>}
        <div className="hint">quick matches: algorithm catalog only · enter opens full search (algorithms, protocols, hardware, findings) · esc to close</div>
      </div>
    </div>
  );
}
