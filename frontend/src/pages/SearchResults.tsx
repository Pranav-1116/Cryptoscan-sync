import React, { useEffect, useState } from "react";
import { Panel, PageHead } from "../components/ui.jsx";
import { apiAlgorithmCatalog, apiProtocolCatalog, apiHardwareCatalog, apiRuntimeFindings } from "../lib/api.js";

/* Full search results page — queries the LIVE catalogs and the runtime
   findings store. There is no local/demo index: with an empty estate the
   catalogs (algorithms/protocols/hardware) still return real reference data,
   while findings return zero until a scan runs. */

interface Item { name: string; to: string; meta: string }
interface Group { label: string; icon: string; items: Item[] }

export default function SearchResults() {
  const [q, setQ] = useState("");
  const [input, setInput] = useState("");
  const [groups, setGroups] = useState<Group[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const parse = () => {
      const m = window.location.hash.match(/q=([^&]*)/);
      setQ(decodeURIComponent(m ? m[1] : ""));
    };
    parse();
    window.addEventListener("hashchange", parse);
    return () => window.removeEventListener("hashchange", parse);
  }, []);

  useEffect(() => {
    if (!q.trim()) { setGroups([]); return; }
    let cancelled = false;
    setLoading(true);
    (async () => {
      const term = q.trim();
      const [alg, proto, hw, find] = await Promise.all([
        apiAlgorithmCatalog({ q: term }),
        apiProtocolCatalog(),
        apiHardwareCatalog(),
        apiRuntimeFindings(100),
      ]);
      const out: Group[] = [];
      const algRows = (alg.data?.algorithms ?? []) as any[];
      if (algRows.length) {
        out.push({ label: "Algorithms", icon: "🔐", items: algRows.slice(0, 25).map((a) => ({
          name: `${a.name ?? a.algorithm ?? a.id}${a.family ? ` · ${a.family}` : ""}`,
          to: "#/catalog", meta: a.status ?? a.quantum_status ?? "",
        })) });
      }
      const protoRows = ((proto.data as any)?.protocols ?? (proto.data as any)?.items ?? []) as any[];
      const pHits = protoRows.filter((p) => JSON.stringify(p).toLowerCase().includes(term.toLowerCase()));
      if (pHits.length) {
        out.push({ label: "Protocols", icon: "🌐", items: pHits.slice(0, 25).map((p) => ({
          name: p.name ?? p.protocol ?? p.id, to: "#/protocols", meta: p.status ?? p.category ?? "",
        })) });
      }
      const hwRows = ((hw.data as any)?.devices ?? (hw.data as any)?.items ?? (hw.data as any)?.hardware ?? []) as any[];
      const hHits = hwRows.filter((h) => JSON.stringify(h).toLowerCase().includes(term.toLowerCase()));
      if (hHits.length) {
        out.push({ label: "Hardware", icon: "🔩", items: hHits.slice(0, 25).map((h) => ({
          name: h.name ?? h.model ?? h.id, to: "#/hardware", meta: h.category ?? h.status ?? "",
        })) });
      }
      const fRows = ((find.data as any)?.findings ?? []) as any[];
      const fHits = fRows.filter((f) => JSON.stringify(f).toLowerCase().includes(term.toLowerCase()));
      if (fHits.length) {
        out.push({ label: "Findings", icon: "⚠️", items: fHits.slice(0, 25).map((f) => ({
          name: f.title ?? f.rule_id ?? f.id, to: "#/runtime", meta: f.severity ?? f.status ?? "",
        })) });
      }
      if (!cancelled) setGroups(out);
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [q]);

  const total = groups.reduce((n, g) => n + g.items.length, 0);

  return (
    <>
      <PageHead
        crumb="search"
        title={q ? `Results for “${q}”` : "Search"}
        sub={q ? (loading ? "searching live catalogs…" : `${total} matches across algorithms, protocols, hardware and findings`) : "Type a query in the header search box"}
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
      {total === 0 && q && !loading && (
        <Panel title="No matches" sub={`nothing found for “${q}”`}>
          <div className="dim" style={{ fontSize: 13.5 }}>
            Try an algorithm (RSA, AES, ML-KEM), a protocol, a hardware class, or a finding id. Findings appear only after a real scan.
          </div>
        </Panel>
      )}
      {groups.map((g, gi) => (
        <Panel key={g.label} title={`${g.icon} ${g.label}`} sub={`${g.items.length} matches`} className="mt" style={gi === 0 ? { marginTop: 0 } : undefined}>
          <div style={{ display: "flex", flexDirection: "column" }}>
            {g.items.map((it, i) => (
              <a key={`${it.name}-${i}`} href={it.to} style={{ display: "flex", justifyContent: "space-between", gap: 14, padding: "7px 10px", borderRadius: 8, color: "var(--text)" }}>
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
