import React, { useEffect, useState } from "react";
import { Panel, PageHead } from "../components/ui.jsx";
import { search } from "../data/initial.js";

/* Full search results page — the overlay shows the top hits, this page
   shows everything for a query (spec §4). */

export default function SearchResults() {
  const [q, setQ] = useState("");
  const [input, setInput] = useState("");

  useEffect(() => {
    const parse = () => {
      const m = window.location.hash.match(/q=([^&]*)/);
      setQ(decodeURIComponent(m ? m[1] : ""));
    };
    parse();
    window.addEventListener("hashchange", parse);
    return () => window.removeEventListener("hashchange", parse);
  }, []);

  const groups = search(q, 100);
  const total = groups.reduce((n, g) => n + g.items.length, 0);

  return (
    <>
      <PageHead
        crumb="search"
        title={q ? `Results for “${q}”` : "Search"}
        sub={q ? `${total} matches across the environment` : "Type a query in the header search box"}
        right={q ? <span className="mono faint" style={{ fontSize: 12 }}>{total} RESULTS</span> : undefined}
      />
      {q && (
        <div className="row" style={{ marginBottom: 16 }}>
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && input.trim()) window.location.hash = `#/search?q=${encodeURIComponent(input.trim())}`; }}
            placeholder="search again…"
            style={{
              flex: 1, maxWidth: 420, background: "rgba(8,12,24,0.8)", border: "1px solid var(--line-strong)",
              borderRadius: 10, color: "var(--text)", fontFamily: "var(--mono)", fontSize: 14, padding: "9px 14px", outline: "none",
            }}
          />
          <button className="btn sm" onClick={() => { if (input.trim()) window.location.hash = `#/search?q=${encodeURIComponent(input.trim())}`; }}>Search</button>
        </div>
      )}
      {total === 0 && q && (
        <Panel title="No matches" sub={`nothing found for “${q}”`}>
          <div className="dim" style={{ fontSize: 13.5 }}>
            Try an algorithm (RSA, AES), a certificate CN, a library, an IP, an asset id or an evidence id.
          </div>
        </Panel>
      )}
      {groups.map((g) => (
        <Panel key={g.label} title={`${g.icon} ${g.label}`} sub={`${g.items.length} matches`} className="mt" style={groups.indexOf(g) === 0 ? { marginTop: 0 } : undefined}>
          <div style={{ display: "flex", flexDirection: "column" }}>
            {g.items.map((it) => (
              <a key={it.name} href={it.to} style={{ display: "flex", justifyContent: "space-between", gap: 14, padding: "7px 10px", borderRadius: 8, color: "var(--text)" }}>
                <span>{it.name}</span>
                <span className="mono faint" style={{ fontSize: 12 }}>{it.meta}</span>
              </a>
            ))}
          </div>
        </Panel>
      ))}
    </>
  );
}
