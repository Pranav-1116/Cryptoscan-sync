import { Link, useSearchParams } from "react-router-dom";
import React, { useEffect, useMemo, useState } from "react";
import { Badge, Bar, Ring } from "../components/ui";
import { apiGraph, apiGraphStats, apiGraphBlastRadius, apiGraphBlastRadiusFromAsset } from "../lib/api";
import AuthenticatedDownload from "../components/AuthenticatedDownload";
import { IconComponent, IconSearch, IconTarget, IconHardware } from "../components/icons";
import CodeCascadePanel from "../components/CodeCascadePanel";
import UnifiedCascadePanel from "../components/UnifiedCascadePanel";
import EdgeManagerPanel from "../components/EdgeManagerPanel";
import SystemCascadeSimulator from "../components/depmap/SystemCascadeSimulator";
import CryptoDependencyMap from "../components/depmap/CryptoDependencyMap";

const KIND_COLOR: Record<string,string> = {
  network:"var(--accent)", infra:"var(--accent)", cloud:"var(--accent)",
  app:"var(--violet)", application:"var(--violet)", process:"var(--violet)",
  cert:"var(--green)", certificate:"var(--green)", hardware:"var(--orange)",
  algo:"var(--red)", algorithm:"var(--red)", lib:"var(--accent)", library:"var(--accent)",
  system:"var(--text)", vendor:"var(--slate)",
};
const gcol = (k:string)=> KIND_COLOR[String(k).toLowerCase()] ?? "var(--line-strong)";

export default function DependencyGraph(){
  const [loading,setLoading]=useState(true);
  const [graphData,setGraphData]=useState<any>({nodes:[], edges:[]});
  const [graphStats,setGraphStats]=useState<any>(null);
  const [selectedNode,setSelectedNode]=useState<any>(null);
  const [blastRadius,setBlastRadius]=useState<any>(null);
  const [calculatingBlast,setCalculatingBlast]=useState(false);
  const [search,setSearch]=useState("");
  const [zoom,setZoom]=useState(1);
  const [layout,setLayout]=useState<"radial"|"grid">("radial");
  const [hover,setHover]=useState<string|null>(null);
  const [searchParams]=useSearchParams();
  const assetParam=searchParams.get("asset");

  useEffect(()=>{
    if(!assetParam) return;
    let alive=true;
    setSelectedNode({id:assetParam, kind:"asset", label:`Crypto asset ${assetParam}`});
    setCalculatingBlast(true);
    apiGraphBlastRadiusFromAsset(assetParam,5).then(res=>{
      if(!alive) return;
      setBlastRadius(res.source==="live" && res.data ? res.data : null);
      setCalculatingBlast(false);
    });
    return ()=>{ alive=false; };
  },[assetParam]);

  useEffect(()=>{
    let alive=true;
    (async()=>{
      setLoading(true);
      try{
        const [gRes,sRes]=await Promise.all([apiGraph(), apiGraphStats()]);
        if(alive){
          if(gRes.source==="live" && gRes.data) setGraphData(gRes.data);
          if(sRes.source==="live" && sRes.data) setGraphStats(sRes.data);
        }
      }catch(e){ console.error(e); } finally{ if(alive) setLoading(false); }
    })();
    return ()=>{ alive=false; };
  },[]);

  const handleSelectNode=async (node:any)=>{
    setSelectedNode(node);
    if(node.kind==="system" || node.id){
      setCalculatingBlast(true);
      try{
        const bRes=await apiGraphBlastRadius(node.id, 2);
        setBlastRadius(bRes.source==="live" && bRes.data ? bRes.data : null);
      }catch{ setBlastRadius(null); } finally{ setCalculatingBlast(false); }
    }
  };

  const nodes = graphData.nodes || [];
  const edges = graphData.edges || [];
  const edgeProvenance: Record<string,number> = {};
  for(const e of edges as Array<Record<string,unknown>>){
    const k=String((e as any)?.provenance || "UNATTRIBUTED").toUpperCase();
    edgeProvenance[k]=(edgeProvenance[k]||0)+1;
  }
  const provenanceSummary = Object.entries(edgeProvenance).sort((a,b)=>b[1]-a[1]).map(([k,v])=> `${v} ${k.toLowerCase().replace(/_/g,"-")}`).join(" · ");

  const filteredNodes = nodes.filter((n:any)=>
    (n.label||n.id||"").toLowerCase().includes(search.toLowerCase()) ||
    (n.kind||"").toLowerCase().includes(search.toLowerCase())
  );

  // visual positions
  const visual = useMemo(()=>{
    if(filteredNodes.length===0) return [] as any[];
    if(layout==="grid"){
      const cols=Math.ceil(Math.sqrt(filteredNodes.length))||1;
      const cellW=150, cellH=56;
      const startX=180 - (cols*cellW)/2;
      return filteredNodes.map((n:any,i:number)=>{
        const r=Math.floor(i/cols), c=i%cols;
        return {n, x:startX + c*cellW + cellW/2, y: 40 + r*cellH };
      });
    }
    // radial
    const cx=180, cy=120, r= Math.min(110, 60+filteredNodes.length*4);
    return filteredNodes.map((n:any,i:number)=>{
      const ang=(i/Math.max(1,filteredNodes.length))*Math.PI*2 - Math.PI/2;
      return {n, x: filteredNodes.length===1?cx: cx + r*Math.cos(ang), y: filteredNodes.length===1?cy: cy + r*Math.sin(ang)*0.7 };
    });
  },[filteredNodes, layout]);

  const blastSet = useMemo(()=> new Set((blastRadius?.systems||[]).map((s:any)=> s.id)),[blastRadius]);

  // Inspector (gap analysis §A: select an asset and inspect its evidence and
  // dependencies). Edges keep their reported provenance; evidence is listed
  // only when the node carries it — an un evidenced connection reads unknown.
  const nodeEdges = useMemo(()=> (
    selectedNode ? (edges as any[]).filter((e:any)=>
      (e.from ?? e.source)===selectedNode.id || (e.to ?? e.target)===selectedNode.id) : []
  ), [edges, selectedNode]);
  const nodeEvidence: string[] = Array.isArray((selectedNode as any)?.evidence_ids)
    ? ((selectedNode as any).evidence_ids as unknown[]).map(String)
    : Array.isArray((selectedNode as any)?.evidenceIds)
      ? ((selectedNode as any).evidenceIds as unknown[]).map(String)
      : [];

  return (
    <div className="page" style={{maxWidth:"1280px", margin:"0 auto", padding:"10px 0 60px"}}>
      {/* Header */}
      <div style={{display:"flex", justifyContent:"space-between", alignItems:"center", padding:"14px 16px", background:"var(--panel)", border:"1px solid var(--line)", borderRadius:"var(--r)", marginBottom:16, flexWrap:"wrap", gap:12}}>
        <div style={{display:"flex", gap:12, alignItems:"center"}}>
          <span style={{width:36,height:36, borderRadius:10, display:"grid", placeItems:"center", background:"color-mix(in srgb, var(--accent) 14%, transparent)", border:"1px solid var(--accent)"}}><IconComponent size={16} style={{color:"var(--accent)"}}/></span>
          <div>
            <div style={{fontSize:10, letterSpacing:.12, fontFamily:"var(--mono)", color:"var(--accent)"}}>DETERMINISTIC TOPOLOGY · LIVE BFS · NO INFERENCE</div>
            <h1 style={{fontSize:22, fontWeight:700, margin:"2px 0 2px", lineHeight:1}}>Cryptographic Dependency Graph</h1>
            <div style={{fontSize:12, color:"var(--dim)"}}>Systems → libraries → certs → HSMs — edges by reported provenance · <span style={{color:"var(--accent)"}}>{nodes.length} nodes</span> · <span style={{color:"var(--violet)"}}>{edges.length} edges</span></div>
          </div>
        </div>
        <div style={{display:"flex", gap:10, alignItems:"center", flexWrap:"wrap"}}>
          {!loading && nodes.length>0 && <div style={{display:"flex", alignItems:"center", gap:8}}><Ring pct={edges.length ? Math.min(1, edges.length/Math.max(1,nodes.length*1.5)):0} label={nodes.length} sub="nodes" tone="cyan"/><div style={{fontSize:11, color:"var(--dim)", lineHeight:1.3}}>{edges.length} edges<br/>{provenanceSummary ? <span style={{color:"var(--accent)"}}>{provenanceSummary.split(" · ")[0]}</span> : <span>no edges yet</span>}</div></div>}
          <div style={{display:"flex", flexDirection:"column", gap:8}}>
            <AuthenticatedDownload path="/api/v1/graph" filename="cryptoscan-graph.json" className="btn" style={{fontSize:12, padding:"7px 12px", borderRadius:"var(--r)"}}>Export Graph JSON</AuthenticatedDownload>
            <Link to="/scanners" className="btn primary" style={{textDecoration:"none", fontSize:12, padding:"7px 12px", borderRadius:"var(--r)", textAlign:"center"}}>Discover Topology</Link>
          </div>
        </div>
      </div>

      {/* system → system dependencies + selectable cascade (consumer → provider) */}
      <SystemCascadeSimulator/>
      {/* algorithm → software chain, compact (full explorer lives in Graph explorer) */}
      <CryptoDependencyMap compact/>

      <div style={{display:"grid", gridTemplateColumns:"repeat(auto-fit, minmax(180px,1fr))", gap:12, marginBottom:16}}>
        <div className="panel" style={{padding:"12px 14px", borderTop:"2px solid var(--accent)"}}>
          <div style={{fontSize:10, color:"var(--dim)", letterSpacing:.08, display:"flex", gap:6, alignItems:"center"}}><span className="dot" style={{background:"var(--accent)", width:6,height:6,borderRadius:99}}/>NODES</div>
          <div style={{fontSize:22, fontWeight:800, margin:"4px 0 2px"}}>{loading?"…": (graphStats?.nodes ?? nodes.length)}</div>
          <div style={{fontSize:11, color:"var(--dim)"}}>Systems · libs · certs · HSMs</div>
          {!loading && <Bar value={1} tone="cyan"/>}
        </div>
        <div className="panel" style={{padding:"12px 14px", borderTop:"2px solid var(--cyan)"}}>
          <div style={{fontSize:10, color:"var(--dim)", letterSpacing:.08, display:"flex", gap:6, alignItems:"center"}}><span className="dot" style={{background:"var(--cyan)", width:6,height:6,borderRadius:99}}/>EDGES</div>
          <div style={{fontSize:22, fontWeight:800, color:"var(--cyan)", margin:"4px 0 2px"}}>{loading?"…": (graphStats?.edges ?? edges.length)}</div>
          <div style={{fontSize:11, color:"var(--dim)"}}>{loading?"…": (provenanceSummary || "no edges yet")}</div>
          {!loading && edges.length>0 && <Bar value={Math.min(1, edges.length/Math.max(1,(graphStats?.nodes ?? nodes.length)))} tone="cyan"/>}
          <div style={{fontSize:10, color:"var(--faint)", marginTop:4}}>declared = operator statement · scanner-derived = from scan evidence · unattributed = origin unknown</div>
        </div>
        <div className="panel" style={{padding:"12px 14px", borderTop: loading || graphData.backend ? "2px solid var(--green)" : "2px solid var(--line-strong)"}}>
          <div style={{fontSize:10, color:"var(--dim)", letterSpacing:.08, display:"flex", gap:6, alignItems:"center"}}><span className="dot" style={{background: loading || graphData.backend ? "var(--green)":"var(--slate)", width:6,height:6,borderRadius:99}}/>ENGINE</div>
          <div style={{fontSize:14, fontWeight:700, margin:"6px 0 2px", whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis"}}>{loading?"…": graphData.backend==="memory"?"Deterministic Memory": graphData.backend? `Neo4j (${graphData.backend})`:"Not reported"}</div>
          <div style={{fontSize:11, color: loading || graphData.backend ? "var(--green)":"var(--dim)"}}>{loading || graphData.backend ? "Fail-closed BFS ready" : "Backend not reported"}</div>
        </div>
        <div className="panel" style={{padding:"12px 14px", borderTop:"2px solid var(--violet)"}}>
          <div style={{fontSize:10, color:"var(--dim)", letterSpacing:.08, display:"flex", gap:6, alignItems:"center"}}><span className="dot" style={{background:"var(--violet)", width:6,height:6,borderRadius:99}}/>BLAST READY</div>
          <div style={{fontSize:22, fontWeight:800, margin:"4px 0 2px"}}>{blastRadius ? blastRadius.systems?.length ?? 0 : "—"}</div>
          <div style={{fontSize:11, color:"var(--dim)"}}>{selectedNode ? blastRadius ? `${selectedNode.label||selectedNode.id} downstream` : "Traversal unavailable — impact unknown" : "select a node"}</div>
          <Bar value={selectedNode && blastRadius ? Math.min(1, (blastRadius.systems?.length||0)/8) : 0} tone="violet"/>
        </div>
      </div>

      {selectedNode && (
        <div className="panel" style={{padding:"12px 14px", marginBottom:16}} data-testid="node-inspector">
          <div style={{fontSize:10, letterSpacing:.08, color:"var(--dim)"}}>
            INSPECTOR · {selectedNode.label || selectedNode.id}
          </div>
          <div style={{display:"grid", gridTemplateColumns:"1fr 1fr", gap:16, marginTop:8}}>
            <div>
              <div style={{fontSize:11, textTransform:"uppercase", color:"var(--dim)"}}>Dependencies</div>
              {nodeEdges.length ? (
                <ul style={{margin:"4px 0 0", paddingLeft:16, fontSize:11.5}} data-testid="node-dependencies">
                  {nodeEdges.map((e:any, i:number)=> {
                    const other = (e.from ?? e.source)===selectedNode.id ? (e.to ?? e.target) : (e.from ?? e.source);
                    return (
                      <li key={i}>
                        {String(other)} — {String(e.label ?? e.predicate ?? "related to")}{" "}
                        <span style={{color:"var(--faint)"}}>({String(e.provenance ?? "UNKNOWN")})</span>
                      </li>
                    );
                  })}
                </ul>
              ) : (
                <div style={{fontSize:11.5, color:"var(--dim)"}}>
                  no dependency edges are recorded for this node — unknown, not isolated
                </div>
              )}
            </div>
            <div>
              <div style={{fontSize:11, textTransform:"uppercase", color:"var(--dim)"}}>Evidence</div>
              {nodeEvidence.length ? (
                <ul style={{margin:"4px 0 0", paddingLeft:16, fontSize:11.5, fontFamily:"var(--mono)"}} data-testid="node-evidence">
                  {nodeEvidence.map((id)=> <li key={id}>{id}</li>)}
                </ul>
              ) : (
                <div style={{fontSize:11.5, color:"var(--dim)"}}>
                  no evidence is attached to this node's connections: unknown, never a clean provenance
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Visual workspace */}
      <div style={{display:"grid", gridTemplateColumns:"1.2fr 1fr", gap:20}}>
        {/* Left */}
        <div className="panel" style={{padding:0, overflow:"hidden"}}>
          <div style={{display:"flex", justifyContent:"space-between", alignItems:"center", gap:10, flexWrap:"wrap", padding:"10px 12px", background:"var(--bg-2)", borderBottom:"1px solid var(--line)"}}>
            <div style={{display:"flex", alignItems:"center", gap:8}}><IconComponent size={14} style={{color:"var(--accent)"}}/><span style={{fontSize:12, fontWeight:700}}>Topology Elements</span><Badge tone={nodes.length?"cyan":"slate"}>{filteredNodes.length} / {nodes.length}</Badge>{selectedNode && <Badge tone="amber">{selectedNode.label||selectedNode.id} ●</Badge>}</div>
            <div style={{display:"flex", gap:6, alignItems:"center"}}>
              <button onClick={()=>setLayout("radial")} style={{fontSize:11, padding:"4px 8px", borderRadius:"var(--r)", border:`1px solid ${layout==="radial"?"var(--accent)":"var(--line)"}`, background: layout==="radial"?"var(--panel-2)":"transparent", color: layout==="radial"?"var(--accent)":"var(--dim)", cursor:"pointer"}}>Radial</button>
              <button onClick={()=>setLayout("grid")} style={{fontSize:11, padding:"4px 8px", borderRadius:"var(--r)", border:`1px solid ${layout==="grid"?"var(--accent)":"var(--line)"}`, background: layout==="grid"?"var(--panel-2)":"transparent", color: layout==="grid"?"var(--accent)":"var(--dim)", cursor:"pointer"}}>Grid</button>
              <div style={{width:1,height:16,background:"var(--line)"}}/>
              <button onClick={()=>setZoom(z=> Math.min(1.4, +(z+0.1).toFixed(1)))} style={{fontSize:12, padding:"4px 8px", border:"1px solid var(--line)", background:"var(--panel)", borderRadius:"var(--r)", cursor:"pointer"}}>+</button>
              <span style={{fontFamily:"var(--mono)", fontSize:11, color:"var(--dim)", minWidth:32, textAlign:"center"}}>{Math.round(zoom*100)}%</span>
              <button onClick={()=>setZoom(z=> Math.max(0.7, +(z-0.1).toFixed(1)))} style={{fontSize:12, padding:"4px 8px", border:"1px solid var(--line)", background:"var(--panel)", borderRadius:"var(--r)", cursor:"pointer"}}>−</button>
              <button onClick={()=>setZoom(1)} style={{fontSize:10, padding:"4px 7px", border:"1px solid var(--line)", background:"transparent", borderRadius:"var(--r)", cursor:"pointer"}}>[ ]</button>
            </div>
          </div>

          <div style={{display:"flex", alignItems:"center", gap:8, padding:"8px 12px", borderBottom:"1px solid var(--line)", background:"var(--panel)"}}>
            <IconSearch size={13} style={{color:"var(--faint)"}}/>
            <input type="text" placeholder="Filter nodes — name, kind, id…" value={search} onChange={e=>setSearch(e.target.value)} className="inp" style={{flex:1, fontSize:12, padding:"7px 10px"}}/>
            {search && <button onClick={()=>setSearch("")} style={{fontSize:11, padding:"4px 8px", border:"1px solid var(--line)", background:"var(--panel-2)", borderRadius:"var(--r)", cursor:"pointer"}}>Clear</button>}
            <span style={{fontSize:11, color:"var(--faint)"}}>
              {visual.length} shown{edges.length > 80 ? ` · first 80 of ${edges.length} edges drawn` : ""}
            </span>
          </div>

          {/* mini canvas */}
          {filteredNodes.length>0 && (
            <div style={{padding:10, background:"var(--bg-2)", borderBottom:"1px solid var(--line)", overflow:"auto"}}>
              <div style={{transform:`scale(${zoom})`, transformOrigin:"top center", transition:"transform 160ms ease"}}>
                <svg viewBox="0 0 360 240" width="100%" style={{minWidth:360, height:220, background:"var(--panel)", border:"1px solid var(--line)", borderRadius:"var(--r)", display:"block"}}>
                  {edges.slice(0,80).map((e:any,i:number)=>{
                    const f = visual.find((v:any)=> v.n.id===e.from || v.n.id===e.source);
                    const t = visual.find((v:any)=> v.n.id===e.to || v.n.id===e.target);
                    if(!f||!t) return null;
                    const sel = selectedNode && (e.from===selectedNode.id || e.to===selectedNode.id || e.source===selectedNode.id || e.target===selectedNode.id);
                    return <line key={i} x1={f.x} y1={f.y} x2={t.x} y2={t.y} stroke={sel? "var(--red)":"var(--line-strong)"} strokeWidth={sel?1.6:0.9} opacity={sel?1:0.4}/>;
                  })}
                  {visual.map(({n,x,y}:any)=>{
                    const isSel = selectedNode?.id===n.id;
                    const isBlast = blastSet.has(n.id);
                    const isHover = hover===n.id;
                    return (
                      <g key={n.id} onClick={()=>handleSelectNode(n)} onMouseEnter={()=>setHover(n.id)} onMouseLeave={()=>setHover(null)} style={{cursor:"pointer"}}>
                        <circle cx={x} cy={y} r={isSel?10: isBlast?8:6} fill={isSel?"var(--red)": isBlast?"var(--accent)": gcol(n.kind)} stroke={isHover?"var(--text)": "var(--panel)"} strokeWidth={isHover?1.5:1} opacity={0.95}/>
                        <text x={x} y={y+16} textAnchor="middle" style={{fontSize:7.5, fill:"var(--dim)", fontFamily:"var(--mono)"}}>{String(n.label||n.id).slice(0,10)}</text>
                      </g>
                    );
                  })}
                </svg>
              </div>
              <div style={{fontSize:10, color:"var(--faint)", marginTop:6, display:"flex", justifyContent:"space-between"}}><span>● selected · ◆ blast · click dot to inspect</span><span style={{fontFamily:"var(--mono)"}}>{layout} · {Math.round(zoom*100)}%</span></div>
            </div>
          )}

          <div style={{display:"flex", flexDirection:"column", gap:8, maxHeight:480, overflowY:"auto", padding:10, background:"var(--panel)"}}>
            {filteredNodes.map((n:any)=>{
              const isSelected = selectedNode?.id===n.id;
              const isBlast = blastSet.has(n.id);
              return (
                <div key={n.id} onClick={()=>handleSelectNode(n)} onMouseEnter={()=>setHover(n.id)} onMouseLeave={()=>setHover(null)}
                  style={{
                    padding:"9px 12px",
                    background: isSelected ? "color-mix(in srgb, var(--accent) 10%, transparent)" : isBlast ? "color-mix(in srgb, var(--accent) 6%, var(--panel-2))" : "var(--panel-2)",
                    border:`1px solid ${isSelected? "var(--accent)" : isBlast? "var(--accent)": "var(--line)"}`,
                    borderLeft:`3px solid ${isSelected? "var(--accent)": n.kind==="certificate"?"var(--green)": n.kind==="hardware"?"var(--orange)":"var(--line-strong)"}`,
                    borderRadius:"var(--r)", cursor:"pointer", display:"flex", justifyContent:"space-between", alignItems:"center",
                    opacity: hover && hover!==n.id && !isBlast && !isSelected ? 0.55 :1
                  }}>
                  <div style={{minWidth:0, flex:1}}>
                    <div style={{fontSize:13, fontWeight:600, color:"var(--text)", fontFamily:"var(--mono)", whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis"}}>[<span style={{color: isSelected? "var(--accent)": isBlast? "var(--accent)":"var(--text)"}}>{n.label||n.id}</span>] {isBlast && <span style={{fontSize:9, background:"var(--accent)", color:"var(--on-accent)", padding:"1px 5px", borderRadius:99, marginLeft:4}}>BLAST</span>}</div>
                    <div style={{fontSize:11, color:"var(--dim)"}}>Kind: {n.kind||"system"} · In:{n.in_degree??0} Out:{n.out_degree??0}</div>
                  </div>
                  <Badge variant={n.kind==="hardware"?"warning": n.kind==="certificate"?"info":"neutral"}>{(n.kind||"node").toUpperCase()}</Badge>
                </div>
              );
            })}
            {filteredNodes.length===0 && !loading && (
              <div style={{textAlign:"center", padding:40, color:"var(--dim)"}}>
                <div style={{fontSize:14, fontWeight:600, color:"var(--text)", marginBottom:4}}>No topology nodes</div>
                <p style={{margin:"0 0 14px", fontSize:12.5}}>Register systems and run discovery to populate links.</p>
                <Link to="/scanners" className="btn sm primary" style={{textDecoration:"none"}}>Launch Scanners</Link>
              </div>
            )}
          </div>
        </div>

        {/* Right */}
        <div className="panel" style={{padding:"14px 16px", borderTop:"2px solid var(--red)"}}>
          <div style={{display:"flex", justifyContent:"space-between", alignItems:"center", gap:8, flexWrap:"wrap", marginBottom:8, padding:"8px 10px", background:"var(--bg-2)", borderRadius:"var(--r)", border:"1px solid var(--line)"}}>
            <div style={{display:"flex", alignItems:"center", gap:8}}><IconTarget size={14} style={{color:"var(--red)"}}/><span style={{fontSize:12, fontWeight:700}}>Blast Radius & Impact</span><Badge tone={blastRadius? "red":"slate"}>{blastRadius? `${blastRadius.systems?.length??0} impacted`:"select node"}</Badge></div>
            <span style={{fontSize:11, color:"var(--dim)"}}>Exact BFS · downstream</span>
          </div>

          {selectedNode ? (
            <div style={{display:"flex", flexDirection:"column", gap:14}}>
              {selectedNode.kind==="asset" && (
                <div style={{fontSize:12, color:"var(--dim)", lineHeight:1.5}}>Asset start — walk fans out from every system using this asset (declared SystemAsset links).{" "}<Link to="/assets" style={{color:"var(--accent)"}}>Back to assets</Link>{blastRadius?.owning_systems?.length ? ` · ${blastRadius.owning_systems.length} owners` : ""}</div>
              )}
              <div style={{padding:12, background:"var(--bg-2)", border:"1px solid var(--line)", borderRadius:"var(--r)", borderLeft:`3px solid ${gcol(selectedNode.kind)}`}}>
                <div style={{fontSize:11, color:"var(--dim)", textTransform:"uppercase", letterSpacing:.06}}>Selected</div>
                <div style={{fontSize:15, fontWeight:700, color:"var(--text)", margin:"3px 0", fontFamily:"var(--mono)"}}>{selectedNode.label||selectedNode.id}</div>
                <div style={{fontSize:12, color:"var(--dim)"}}>ID: <span style={{fontFamily:"var(--mono)", color:"var(--text)"}}>{selectedNode.id}</span> · kind <b style={{color:"var(--text)"}}>{selectedNode.kind||"system"}</b></div>
                {selectedNode.source==="cryptoscan-systems.yml" && <div style={{fontSize:11, color:"var(--dim)", marginTop:4}}>Declared in code (cryptoscan-systems.yml)</div>}
              </div>

              {selectedNode.code_cascade && (
                <div style={{padding:12, background:"var(--bg-2)", border:"1px solid var(--line)", borderRadius:"var(--r)"}}>
                  <div style={{fontSize:11, color:"var(--dim)", textTransform:"uppercase"}}>Code crypto (latest scan)</div>
                  <div style={{display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:8, margin:"6px 0"}}>
                    <div><div style={{fontSize:11,color:"var(--dim)"}}>Providers</div><div style={{fontWeight:700}}>{selectedNode.code_cascade.providers}</div></div>
                    <div><div style={{fontSize:11,color:"var(--dim)"}}>Weak</div><div style={{fontWeight:700, color: selectedNode.code_cascade.weak_parameters? "var(--red)":undefined}}>{selectedNode.code_cascade.weak_parameters}</div></div>
                    <div><div style={{fontSize:11,color:"var(--dim)"}}>Wave</div><div style={{fontWeight:700}}>{selectedNode.code_cascade.earliest_wave ?? "—"}</div></div>
                  </div>
                  <div style={{fontSize:12}}>{(selectedNode.code_cascade.algorithms||[]).slice(0,8).join(", ")||"—"}</div>
                  <div style={{fontSize:11, color:"var(--dim)", marginTop:4}}>scan {selectedNode.code_cascade.scan_id}</div>
                </div>
              )}

              {calculatingBlast ? (
                <div style={{textAlign:"center", padding:20, color:"var(--dim)", fontSize:13}}>Traversing graph…</div>
              ) : blastRadius ? (
                <div style={{display:"flex", flexDirection:"column", gap:10}}>
                  <div style={{display:"grid", gridTemplateColumns:"1fr 1fr", gap:10}}>
                    <div style={{padding:10, background:"var(--bg-2)", borderRadius:"var(--r)", border:"1px solid var(--line)"}}><div style={{fontSize:11,color:"var(--dim)"}}>Impacted</div><div style={{fontSize:20, fontWeight:700, color:"var(--red)"}}>{blastRadius.systems?.length??0}</div><Bar value={Math.min(1,(blastRadius.systems?.length||0)/10)} tone="red"/></div>
                    <div style={{padding:10, background:"var(--bg-2)", borderRadius:"var(--r)", border:"1px solid var(--line)"}}><div style={{fontSize:11,color:"var(--dim)"}}>Max hops</div><div style={{fontSize:20, fontWeight:700}}>{(blastRadius.systems||[]).length>0? `${Math.max(...blastRadius.systems.map((s:any)=>s.hops??0))} hops`:"0 hops"}</div><Bar value={Math.min(1, Math.max(0,...(blastRadius.systems||[]).map((s:any)=>s.hops??0))/6)} tone="cyan"/></div>
                  </div>
                  {blastRadius.provenance_counts && (
                    <div style={{fontSize:11, color:"var(--dim)", lineHeight:1.5, padding:"8px 10px", background:"var(--panel-2)", border:"1px solid var(--line)", borderRadius:"var(--r)"}}>
                      Path edges: {Object.entries(blastRadius.provenance_counts as Record<string,number>).filter(([,v])=>Number(v)>0).map(([k,v])=> `${Number(v)} ${String(k).toLowerCase().replace(/_/g,"-")}`).join(" · ") || "none"} — declared edges are operator statements, not observed traffic.
                    </div>
                  )}
                  {blastRadius.systems && blastRadius.systems.length>0 && (
                    <div>
                      <div style={{fontSize:12, fontWeight:600, marginBottom:6, color:"var(--faint)"}}>Downstream Dependents:</div>
                      <div style={{display:"flex", flexDirection:"column", gap:4, maxHeight:220, overflowY:"auto", paddingRight:2}}>
                        {blastRadius.systems.map((s:any, idx:number)=>(
                          <div key={idx} style={{fontSize:12, padding:"6px 8px", background: idx===0? "color-mix(in srgb, var(--accent) 10%, var(--panel-2))":"var(--bg-2)", border:"1px solid var(--line)", borderRadius:"var(--r)", display:"flex", justifyContent:"space-between"}}>
                            <span>↳ {s.name||s.id}</span><span style={{color:"var(--dim)", fontFamily:"var(--mono)"}}>{s.hops} hop{s.hops===1?"":"s"}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div style={{padding:14, background:"var(--bg-2)", borderRadius:"var(--r)", fontSize:12.5, color:"var(--dim)", border:"1px solid var(--line)"}}>No traversal result — not linked to any system, or graph offline. Blast is unknown, not zero.</div>
              )}
              <Link to="/what-if" className="btn sm primary" style={{textDecoration:"none", display:"block", textAlign:"center"}}>Explore What-If Migration</Link>
            </div>
          ) : (
            <div style={{textAlign:"center", padding:40, color:"var(--dim)", fontSize:13}}>Select a node from the topology on the left to calculate blast radius.</div>
          )}
        </div>
      </div>

      <CodeCascadePanel/>
      <UnifiedCascadePanel/>
      <EdgeManagerPanel/>
    </div>
  );
}
