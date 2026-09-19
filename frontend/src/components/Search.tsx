/* Global search — one box across the entire environment (spec §4).
 * Queries the LIVE algorithm catalog (the deterministic reference KB); with
 * an empty estate that is still real reference data. No local/demo index. */

import React, { useEffect, useRef, useState } from "react";
import { apiAlgorithmCatalog } from "../lib/api.js";

interface Item { name: string; to: string; meta: string }
interface Group { label: string; icon: string; items: Item[] }

export default function SearchOverlay({ onClose }: { onClose: () => void }) {
  const [q, setQ] = useState("");
  const [groups, setGroups] = useState<Group[]>([]);
  const [searching, setSearching] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

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
          to: "#/catalog",
          meta: a.status ?? a.quantum_status ?? "",
        }));
        setGroups(items.length ? [{ label: "Algorithms", icon: "🔐", items }] : []);
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
          placeholder="Search: algorithm (RSA, AES, ML-KEM) · library · protocol · hardware · certificate · asset"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        {q.trim() && !searching && total === 0 ? (
          <div className="empty">no matches for “{q}” — run a scan to make findings/assets searchable</div>
        ) : searching ? (
          <div className="empty">searching live catalog…</div>
        ) : (
          <div className="groups">
            {groups.map((g) => (
              <div className="group" key={g.label}>
                <div className="glabel">{g.icon} {g.label} · {g.items.length}</div>
                {g.items.map((it, i) => (
                  <a className="gitem" key={`${it.name}-${i}`} href={it.to} onClick={onClose}>
                    <span>{it.name}</span>
                    <span className="meta">{it.meta}</span>
                  </a>
                ))}
              </div>
            ))}
          </div>
        )}
        <div className="hint">esc to close · searches the live algorithm catalog; findings and assets appear after a real scan</div>
      </div>
    </div>
  );
}
