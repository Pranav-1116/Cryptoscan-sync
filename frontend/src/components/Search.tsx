/* Global search — one box across the entire environment (spec §4). */

import React, { useEffect, useRef, useState } from "react";
import { search } from "../data/initial.js";

export default function SearchOverlay({ onClose }: { onClose: () => void }) {
  const [q, setQ] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const groups = search(q, 6);
  const total = groups.reduce((n, g) => n + g.items.length, 0);

  return (
    <div className="searchov" onClick={onClose}>
      <div className="box" onClick={(e) => e.stopPropagation()}>
        <input
          ref={inputRef}
          placeholder="Search: IP · hostname · application · certificate · algorithm · RSA · AES · HSM · TPM · cloud · vendor · library · CBOM · evidence · asset"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        {q.trim() && total === 0 ? (
          <div className="empty">no matches for “{q}”</div>
        ) : (
          <div className="groups">
            {groups.map((g) => (
              <div className="group" key={g.label}>
                <div className="glabel">{g.icon} {g.label} · {g.items.length}</div>
                {g.items.map((it) => (
                  <a className="gitem" key={it.name} href={it.to} onClick={onClose}>
                    <span>{it.name}</span>
                    <span className="meta">{it.meta}</span>
                  </a>
                ))}
              </div>
            ))}
          </div>
        )}
        <div className="hint">esc to close · searches algorithms, certificates, libraries, hardware, cloud, vendors, network, assets, CBOM refs and evidence IDs</div>
      </div>
    </div>
  );
}
