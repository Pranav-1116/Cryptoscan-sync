import { Link } from "react-router-dom";
import React, { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { Panel, Badge, Table, PageHead, Bar, Ring } from "../components/ui.jsx";
import { apiBlast, LiveBadge } from "../lib/api.js";
import { useLive } from "../lib/useLive.js";
import { motion, AnimatePresence } from "framer-motion";
import { EASE, useMotionOK, CountUp } from "../lib/motion";
import {
  IconSearch, IconTarget, IconComponent, IconCertificate, IconHardware,
  IconCloud, IconNetwork, IconCode, IconInfo, IconSettings, IconTrendUp,
  IconTrendDown, ICON_SM
} from "../components/icons";

/* ─── Graph Explorer — enterprise visual console ──── */

interface RawNode { id: string; label?: string; name?: string; group?: string; kind?: string; criticality?: string; [k:string]:unknown }
interface RawEdge { from?: string; to?: string; source?: string; target?: string; label?: string; relationship?: string; provenance?: string; }
interface GNode { id: string; label: string; sub: string; x:number; y:number; kind:string; crit?:string; degreeIn:number; degreeOut:number; }
type LayoutMode = "radial" | "hierarchical" | "force" | "grid";

const KIND_TONE: Record<string,string> = {
  system:"violet", cert:"green", certificate:"green", infra:"blue", network:"blue",
  cloud:"cyan", app:"violet", application:"violet", process:"violet",
  lib:"cyan", library:"cyan", algo:"red", algorithm:"red", vendor:"slate", owner:"green", hardware:"orange", risk:"red",
};
const KIND_COLOR: Record<string,string> = {
  network:"var(--accent)", infra:"var(--accent)", cloud:"var(--accent)",
  app:"var(--violet)", application:"var(--violet)", process:"var(--violet)",
  crypto:"var(--accent)", cert:"var(--green)", certificate:"var(--green)",
  hardware:"var(--orange)", algo:"var(--red)", algorithm:"var(--red)",
  lib:"var(--accent)", library:"var(--accent)", risk:"var(--red)",
  vendor:"var(--slate)", owner:"var(--text)", system:"var(--text)",
};
const graphColor = (k:string)=> KIND_COLOR[String(k).toLowerCase()] ?? "var(--line-strong)";
const KIND_ICON: Record<string,string> = {
  system:"◆", cloud:"☁", network:"⬢", infra:"⬣", app:"▣", application:"▣", process:"▭",
  certificate:"⬔", cert:"⬔", library:"▤", lib:"▤", hardware:"⬓", algorithm:"⬥", algo:"⬥", vendor:"⬒", owner:"⬔"
};

/* layouts */
function layoutRadial(nodes: RawNode[]): GNode[]{
  const cx=420, cy=220, r= nodes.length>1 ? Math.min(180, 100+nodes.length*6) : 0;
  return nodes.map((n,i)=>{
    const ang=(i/Math.max(1,nodes.length))*Math.PI*2 - Math.PI/2;
    return { id:n.id, label:String(n.label??n.name??n.id), sub:String(n.group??n.kind??""), kind:String(n.group??n.kind??"app"), crit:String((n as any).criticality??""), x:nodes.length===1?cx:cx+r*Math.cos(ang), y:nodes.length===1?cy:cy+r*Math.sin(ang)*0.68, degreeIn:0, degreeOut:0 };
  });
}
function layoutHierarchical(nodes: RawNode[], edges: RawEdge[]): GNode[]{
  // BFS levels from sources (in-degree 0)
  const indeg=new Map<string,number>(); nodes.forEach(n=>indeg.set(n.id,0));
  edges.forEach(e=>{ const t=e.to??(e as any).target; if(t&&indeg.has(t)) indeg.set(t, (indeg.get(t)||0)+1);});
  const level=new Map<string,number>(); const q:string[]=[];
  nodes.forEach(n=>{ if((indeg.get(n.id)||0)===0){ level.set(n.id,0); q.push(n.id); }});
  let maxL=0;
  const adj=new Map<string,string[]>();
  edges.forEach(e=>{ const f=e.from??(e as any).source, t=e.to??(e as any).target; if(f&&t){ if(!adj.has(f)) adj.set(f,[]); adj.get(f)!.push(t); }});
  const vis=new Set(q);
  while(q.length){ const cur=q.shift()!; const curL=level.get(cur)||0; for(const nb of adj.get(cur)||[]){ if(!vis.has(nb)){ vis.add(nb); level.set(nb,curL+1); maxL=Math.max(maxL,curL+1); q.push(nb);} } }
  // assign remaining unvisited to max+1
  nodes.forEach(n=>{ if(!level.has(n.id)) level.set(n.id, maxL+1); });
  const buckets=new Map<number, RawNode[]>();
  nodes.forEach(n=>{ const l=level.get(n.id)!; if(!buckets.has(l)) buckets.set(l,[]); buckets.get(l)!.push(n);});
  const levels=Array.from(buckets.keys()).sort((a,b)=>a-b);
  const out:GNode[]=[];
  const colW= 160, rowH=86;
  levels.forEach((lvl, li)=>{
    const bucket=buckets.get(lvl)!;
    const totalW= bucket.length*colW;
    const startX= 420 - totalW/2;
    bucket.forEach((n, idx)=>{
      out.push({ id:n.id, label:String(n.label??n.name??n.id), sub:String(n.group??n.kind??""), kind:String(n.group??n.kind??"app"), crit:String((n as any).criticality??""), x:startX+ idx*colW + colW/2, y: 70 + li*rowH, degreeIn:0, degreeOut:0 });
    });
  });
  return out;
}
function layoutGrid(nodes: RawNode[]): GNode[]{
  const cols=Math.ceil(Math.sqrt(nodes.length))||1;
  const cellW=170, cellH=78;
  const totalW=cols*cellW;
  const startX= 420 - totalW/2;
  return nodes.map((n,i)=>{
    const r=Math.floor(i/cols), c=i%cols;
    return { id:n.id, label:String(n.label??n.name??n.id), sub:String(n.group??n.kind??""), kind:String(n.group??n.kind??"app"), crit:String((n as any).criticality??""), x:startX + c*cellW + cellW/2, y:70+r*cellH, degreeIn:0, degreeOut:0 };
  });
}
function layoutForce(nodes: RawNode[], edges: RawEdge[]): GNode[]{
  // simple iterative force — deterministic seed based on index
  const N=nodes.length;
  const pos = nodes.map((_,i)=>({ x: 420 + ( (i*37)%200 -100), y: 180 + ((i*57)%140 -70), vx:0, vy:0 }));
  const idToIdx=new Map(nodes.map((n,i)=>[n.id,i]));
  for(let iter=0; iter<90; iter++){
    // repulsion
    for(let i=0;i<N;i++) for(let j=i+1;j<N;j++){
      const dx=pos[i].x-pos[j].x, dy=pos[i].y-pos[j].y;
      const d=Math.sqrt(dx*dx+dy*dy)||1;
      const f= 900/(d*d);
      const fx=f*dx/d, fy=f*dy/d;
      pos[i].vx+=fx; pos[i].vy+=fy; pos[j].vx-=fx; pos[j].vy-=fy;
    }
    // attraction on edges
    edges.forEach(e=>{
      const a=idToIdx.get(String(e.from??(e as any).source??"")), b=idToIdx.get(String(e.to??(e as any).target??""));
      if(a==null||b==null) return;
      const dx=pos[b].x-pos[a].x, dy=pos[b].y-pos[a].y;
      const d=Math.sqrt(dx*dx+dy*dy)||1;
      const ideal=110;
      const f= 0.025 * (d - ideal);
      const fx=f*dx/d, fy=f*dy/d;
      pos[a].vx+=fx; pos[a].vy+=fy; pos[b].vx-=fx; pos[b].vy-=fy;
    });
    // centering
    for(let i=0;i<N;i++){
      const dx=420-pos[i].x, dy=180-pos[i].y;
      pos[i].vx+=dx*0.006; pos[i].vy+=dy*0.006;
      pos[i].vx*=0.88; pos[i].vy*=0.88;
      pos[i].x+=pos[i].vx; pos[i].y+=pos[i].vy;
      pos[i].x=Math.max(90, Math.min(750, pos[i].x));
      pos[i].y=Math.max(40, Math.min(360, pos[i].y));
    }
  }
  return nodes.map((n,i)=>({ id:n.id, label:String(n.label??n.name??n.id), sub:String(n.group??n.kind??""), kind:String(n.group??n.kind??"app"), crit:String((n as any).criticality??""), x:pos[i].x, y:pos[i].y, degreeIn:0, degreeOut:0 }));
}


export default function Graph(){
  const graph = useLive<{nodes:RawNode[]; edges:RawEdge[]; backend?:string}>("/api/v1/graph", {nodes:[], edges:[]});
  const stats = useLive<any>("/api/v1/graph/stats", {});
  const motionOK = useMotionOK();

  const [sel, setSel] = useState<string|null>(null);
  const [hover, setHover] = useState<string|null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({x:0,y:0});
  const [layoutMode, setLayoutMode] = useState<LayoutMode>("radial");
  const [kindFilter, setKindFilter] = useState<string>("all");
  const [q, setQ] = useState("");
  const [showLegend, setShowLegend] = useState(true);
  const [showMinimap, setShowMinimap] = useState(true);
  const [hops, setHops] = useState(6);
  const [play, setPlay] = useState(false);
  const [playStep, setPlayStep] = useState(0);
  const svgRef = useRef<SVGSVGElement>(null);

  const rawNodes = graph.data.nodes ?? [];
  const rawEdges = graph.data.edges ?? [];

  const EDGES = useMemo(()=> (rawEdges.map(e=>({ from:String(e.from??(e as any).source??""), to:String(e.to??(e as any).target??""), label:String(e.label??e.relationship??""), provenance:String((e as any).provenance??"") })).filter(e=>e.from&&e.to)),[rawEdges]);
  const kindSet = useMemo(()=> Array.from(new Set(rawNodes.map(n=> String(n.kind??n.group??"system").toLowerCase()))).sort(),[rawNodes]);

  // degree calc
  const deg = useMemo(()=>{
    const m=new Map<string,{in:number,out:number}>();
    rawNodes.forEach(n=> m.set(n.id,{in:0,out:0}));
    EDGES.forEach(e=>{ const a=m.get(e.from), b=m.get(e.to); if(a) a.out++; if(b) b.in++; });
    return m;
  },[rawNodes,EDGES]);

  const NODES = useMemo(()=>{
    let base: GNode[];
    if(layoutMode==="hierarchical") base=layoutHierarchical(rawNodes, rawEdges);
    else if(layoutMode==="grid") base=layoutGrid(rawNodes);
    else if(layoutMode==="force") base=layoutForce(rawNodes, rawEdges);
    else base=layoutRadial(rawNodes);
    return base.map(n=>{ const d=deg.get(n.id); return {...n, degreeIn:d?.in??0, degreeOut:d?.out??0}; });
  },[rawNodes, rawEdges, layoutMode, deg]);

  const byId = useMemo(()=> new Map(NODES.map(n=>[n.id,n] as const)),[NODES]);
  const adjOut = useMemo(()=>{ const m=new Map<string,string[]>(); EDGES.forEach(e=>{ if(!m.has(e.from)) m.set(e.from,[]); m.get(e.from)!.push(e.to);}); return m;},[EDGES]);
  const adjIn = useMemo(()=>{ const m=new Map<string,string[]>(); EDGES.forEach(e=>{ if(!m.has(e.to)) m.set(e.to,[]); m.get(e.to)!.push(e.from);}); return m;},[EDGES]);

  const bfs = useCallback((start:string, maxHops:number)=>{
    const dist=new Map<string,number>(); dist.set(start,0);
    const q=[start];
    const levels: string[][]=[[]];
    while(q.length){
      const cur=q.shift()!; const d=dist.get(cur)!; if(d>=maxHops) continue;
      for(const nb of adjOut.get(cur)||[]){
        if(!dist.has(nb)){ dist.set(nb,d+1); if(!levels[d+1]) levels[d+1]=[]; levels[d+1].push(nb); q.push(nb); }
      }
    }
    levels[0]=[start];
    return { dist, levels: levels.filter(Boolean) };
  },[adjOut]);

  const blastInfo = useMemo(()=> sel ? bfs(sel, hops) : null,[sel,bfs,hops]);
  const blastSet = useMemo(()=> blastInfo ? new Set(Array.from(blastInfo.dist.keys()).filter(k=>k!==sel)) : new Set<string>(),[blastInfo,sel]);
  const upstream = useMemo(()=>{
    if(!sel) return new Set<string>();
    const out=new Set<string>(); const walk=(id:string)=> (adjIn.get(id)||[]).forEach(p=>{ if(!out.has(p)){ out.add(p); walk(p); }}); walk(sel); return out;
  },[sel,adjIn]);

  // metrics
  const density = useMemo(()=> NODES.length>1 ? EDGES.length / (NODES.length*(NODES.length-1)) : 0,[NODES,EDGES]);
  const avgDeg = useMemo(()=> NODES.length ? +(EDGES.length*2 / NODES.length).toFixed(1) : 0,[NODES,EDGES]);
  const components = useMemo(()=>{
    const vis=new Set<string>(); let comps=0;
    const undir=new Map<string,Set<string>>(); rawNodes.forEach(n=> undir.set(n.id,new Set()));
    EDGES.forEach(e=>{ undir.get(e.from)?.add(e.to); undir.get(e.to)?.add(e.from); });
    for(const n of rawNodes){ if(vis.has(n.id)) continue; comps++; const stack=[n.id]; vis.add(n.id); while(stack.length){ const cur=stack.pop()!; for(const nb of undir.get(cur)||[]) if(!vis.has(nb)){ vis.add(nb); stack.push(nb); } } }
    return comps;
  },[rawNodes,EDGES]);
  const orphan = stats.data?.orphan_system_count ?? NODES.filter(n=> n.degreeIn===0 && n.degreeOut===0).length;

  // play animation
  useEffect(()=>{
    if(!play || !blastInfo) return;
    setPlayStep(0);
    let s=0; const max=blastInfo.levels.length-1;
    const t=setInterval(()=>{ s++; if(s>max){ setPlay(false); clearInterval(t);} else setPlayStep(s); }, 420);
    return ()=> clearInterval(t);
  },[play, blastInfo]);

  // filter
  const filteredIds = useMemo(()=>{
    const qq=q.trim().toLowerCase();
    return new Set(NODES.filter(n=>{
      const kindOk = kindFilter==="all" || n.kind.toLowerCase()===kindFilter;
      const qOk = !qq || n.label.toLowerCase().includes(qq) || n.id.toLowerCase().includes(qq) || n.kind.toLowerCase().includes(qq);
      return kindOk && qOk;
    }).map(n=>n.id));
  },[NODES,q,kindFilter]);

  const selNode = sel ? byId.get(sel) : null;
  const statCounts = stats.data ?? {};

  // pan handlers
  const isPanning=useRef(false), lastPt=useRef({x:0,y:0});
  const onMouseDown=(e:React.MouseEvent)=>{ isPanning.current=true; lastPt.current={x:e.clientX,y:e.clientY}; };
  const onMouseMove=(e:React.MouseEvent)=>{ if(!isPanning.current) return; const dx=e.clientX-lastPt.current.x, dy=e.clientY-lastPt.current.y; lastPt.current={x:e.clientX,y:e.clientY}; setPan(p=>({x:p.x+dx, y:p.y+dy})); };
  const onMouseUp=()=>{ isPanning.current=false; };

  return (
    <>
      <PageHead
        crumb="intelligence / graph explorer"
        title="Graph Explorer"
        sub={`${NODES.length} nodes · ${EDGES.length} edges · ${layoutMode} layout · probe-based, no inference. Click a node → live BFS blast. Drag to pan · scroll to zoom.`}
        right={
          <div className="row" style={{gap:8}}>
            {sel ? <Badge tone="amber">{blastSet.size} IN BLAST</Badge> : <Badge tone="cyan">{NODES.length} NODES</Badge>}
            <Badge tone={graph.data.backend ? "green" : "slate"}>{graph.data.backend ? `● ${graph.data.backend}` : "● no backend"}</Badge>
          </div>
        }
      />

      {/* KPI strip — visual */}
      <div className="grid cols-5" style={{marginBottom:14}}>
        {[
          ["Nodes", statCounts.nodes??NODES.length, `${kindSet.length} kinds`, "cyan", NODES.length?1:0],
          ["Edges", statCounts.edges??EDGES.length, `${EDGES.filter(e=> e.provenance.toLowerCase().includes("manual")).length||0} manual`, "violet", Math.min(1, EDGES.length/40)],
          ["Density", density ? `${(density*100).toFixed(2)}%` : "—", avgDeg? `avg deg ${avgDeg}`: "no links", "cyan", Math.min(1,density*6)],
          ["Components", components || (NODES.length?1:0), components>1?`${components-1} disconnected`:"single fabric", components>1?"amber":"green", components? Math.min(1,1/components):0],
          ["Orphans", orphan, orphan? "isolated — review": "fully linked", orphan?"amber":"green", orphan? Math.min(1,orphan/6):0],
        ].map(([k,v,sub,tone,barV])=>(
          <div key={k as string} className="panel" style={{padding:"12px 14px", borderTop:`2px solid var(--${tone})`}}>
            <div style={{fontSize:10, letterSpacing:.08, color:"var(--dim)", display:"flex", alignItems:"center", gap:6}}><span className="dot" style={{width:6,height:6,borderRadius:99, background:`var(--${tone})`}} />{String(k).toUpperCase()}</div>
            <div style={{fontSize:22, fontWeight:800, margin:"4px 0 2px", fontFamily:"var(--mono)"}}>{typeof v==="number"? <CountUp value={v as number}/>: v as any}</div>
            <div style={{fontSize:11, color:"var(--dim)"}}>{sub as string}</div>
            <div style={{marginTop:8}}><Bar value={barV as number} tone={tone as string} /></div>
          </div>
        ))}
      </div>

      {/* ── Control bar ── */}
      <div className="panel" style={{padding:"10px 12px", display:"flex", gap:10, alignItems:"center", flexWrap:"wrap", marginBottom:12, position:"sticky", top:0, zIndex:5, backdropFilter:"blur(8px)"}}>
        <div style={{display:"flex", alignItems:"center", gap:8, flex:"1 1 220px", minWidth:180, maxWidth:320, background:"var(--bg-2)", border:"1px solid var(--line)", borderRadius:"var(--r)", padding:"6px 10px"}}>
          <IconSearch size={14} style={{color:"var(--faint)", flexShrink:0}}/>
          <input value={q} onChange={e=>setQ(e.target.value)} placeholder="Filter nodes — name, id, kind…" style={{flex:1, background:"transparent", border:0, outline:"none", color:"var(--text)", fontSize:12.5}}/>
          {q && <button onClick={()=>setQ("")} style={{border:0, background:"transparent", color:"var(--dim)", cursor:"pointer", fontSize:12}}>✕</button>}
        </div>

        <div style={{display:"flex", gap:6, flexWrap:"wrap"}}>
          {[
            ["all","All"],
            ...kindSet.slice(0,5).map(k=>[k, k.slice(0,6)] as const)
          ].map(([k,label])=>(
            <button key={k} onClick={()=>setKindFilter(k)} className="btn sm" style={{background: kindFilter===k ? "var(--accent)" : "var(--panel-2)", color: kindFilter===k ? "var(--on-accent)": "var(--text)", borderColor: kindFilter===k ? "var(--accent)" : "var(--line)", padding:"5px 10px", fontSize:11}}>{label} {k!=="all" && `· ${rawNodes.filter(n=> String(n.kind??n.group).toLowerCase()===k).length}`}</button>
          ))}
        </div>

        <div style={{display:"flex", gap:6, alignItems:"center", marginLeft:"auto", flexWrap:"wrap"}}>
          <span style={{fontSize:10, color:"var(--dim)", letterSpacing:.08}}>LAYOUT</span>
          {(["radial","hierarchical","force","grid"] as LayoutMode[]).map(m=>(
            <button key={m} onClick={()=>setLayoutMode(m)} style={{fontSize:11, padding:"6px 10px", borderRadius:"var(--r)", border:`1px solid ${layoutMode===m?"var(--accent)":"var(--line)"}`, background: layoutMode===m?"var(--panel-2)":"transparent", color: layoutMode===m?"var(--accent)":"var(--dim)", cursor:"pointer", textTransform:"capitalize", fontWeight: layoutMode===m?700:500}}>{m}</button>
          ))}
          <span style={{width:1, height:18, background:"var(--line)", margin:"0 4px"}}/>
          <span style={{fontSize:10, color:"var(--dim)"}}>HOPS</span>
          <input type="range" min={1} max={10} value={hops} onChange={e=>setHops(+e.target.value)} style={{width:90, accentColor:"var(--accent)"}}/>
          <span style={{fontFamily:"var(--mono)", fontSize:12, color:"var(--text)", minWidth:18}}>{hops}</span>
          <button className="btn sm" onClick={()=>{ setSel(null); setPan({x:0,y:0}); setZoom(1); }} style={{fontSize:11}}>◎ Fit</button>
          <button className="btn sm" onClick={()=>setShowLegend(v=>!v)} style={{fontSize:11, background: showLegend?"var(--panel-2)":"transparent"}}>Legend {showLegend?"· on":""}</button>
          <button className="btn sm" onClick={()=>setShowMinimap(v=>!v)} style={{fontSize:11}}>Map {showMinimap?"· on":""}</button>
        </div>
      </div>

      {/* ── Canvas + Inspector ── */}
      <div style={{display:"grid", gridTemplateColumns:"1.65fr 0.95fr", gap:14, alignItems:"start"}}>
        {/* Canvas */}
        <Panel title="" sub="" style={{padding:0, overflow:"hidden"}}>
          <div style={{display:"flex", justifyContent:"space-between", alignItems:"center", padding:"10px 12px", borderBottom:"1px solid var(--line)", background:"var(--panel)"}}>
            <div style={{display:"flex", alignItems:"center", gap:8}}>
              <IconComponent size={13} style={{color:"var(--accent)"}}/>
              <span style={{fontSize:12, fontWeight:700}}>Topology Canvas</span>
              <Badge tone="slate">{filteredIds.size}/{NODES.length} visible</Badge>
              <Badge tone={layoutMode==="force"?"violet": layoutMode==="hierarchical"?"cyan":"slate"}>{layoutMode}</Badge>
              {blastSet.size>0 && <Badge tone="amber">{blastSet.size} blast</Badge>}
            </div>
            <div style={{display:"flex", gap:6, alignItems:"center"}}>
              <button className="btn sm" onClick={()=>setZoom(z=> Math.min(1.8, +(z+0.1).toFixed(1)))} style={{minWidth:28}}>+</button>
              <span style={{fontFamily:"var(--mono)", fontSize:11, color:"var(--dim)", minWidth:36, textAlign:"center"}}>{Math.round(zoom*100)}%</span>
              <button className="btn sm" onClick={()=>setZoom(z=> Math.max(0.45, +(z-0.1).toFixed(1)))} style={{minWidth:28}}>−</button>
              <button className="btn sm" onClick={()=>setZoom(1)} style={{fontSize:10}}>[ ]</button>
              {sel && <button className="btn sm primary" onClick={()=>setPlay(p=>!p)} style={{fontSize:11}}>{play? "⏸ Pause" : "▶ Animate blast"}</button>}
            </div>
          </div>

          {NODES.length===0 ? (
            <div style={{minHeight:380, display:"grid", placeItems:"center", padding:24}}>
              <div className="frame" style={{border:"1px dashed var(--line-strong)", borderRadius:"var(--r)", padding:"36px 40px", textAlign:"center", maxWidth:460}}>
                <div style={{fontSize:36, marginBottom:10}}>⬢</div>
                <div style={{fontWeight:700, fontSize:14}}>No graph to render</div>
                <div style={{color:"var(--dim)", fontSize:12.5, marginTop:6, lineHeight:1.6}}>Configure your estate in <Link to="/onboarding">Onboarding</Link> and run a scan. The explorer renders <code>systems → certs → infra → apps → libs → algos</code> from the live CBOM — each node is a verified evidence binding, not a guess.</div>
                <div style={{marginTop:14, display:"flex", gap:8, justifyContent:"center"}}>
                  <Link to="/onboarding" className="btn sm primary">Open onboarding</Link>
                  <Link to="/scanners" className="btn sm">Scan center</Link>
                </div>
              </div>
            </div>
          ) : (
            <div
              onMouseDown={onMouseDown} onMouseMove={onMouseMove} onMouseUp={onMouseUp} onMouseLeave={onMouseUp}
              onWheel={e=>{
                e.preventDefault();
                const delta = e.deltaY >0 ? -0.07 : 0.07;
                setZoom(z=> Math.min(1.8, Math.max(0.45, +(z+delta).toFixed(2))));
              }}
              style={{position:"relative", overflow:"hidden", background:"var(--bg-2)", cursor: isPanning.current?"grabbing":"grab", borderTop:"1px solid var(--line)"}}
            >
              {/* grid bg */}
              <div style={{position:"absolute", inset:0, opacity:0.35, backgroundImage:"radial-gradient(circle, var(--line) 1px, transparent 1px)", backgroundSize:"20px 20px"}}/>

              <div style={{transform:`translate(${pan.x}px, ${pan.y}px) scale(${zoom})`, transformOrigin:"center center", transition: isPanning.current? "none" : "transform 180ms ease"}}>
                <svg ref={svgRef} viewBox="0 0 840 420" width="100%" style={{minWidth:760, height:420, display:"block", background:"transparent"}}>
                  <defs>
                    <marker id="arr" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="var(--line-strong)"/></marker>
                    <marker id="arr-hit" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="var(--red)"/></marker>
                    <marker id="arr-blast" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="var(--accent)"/></marker>
                    <filter id="glow"><feGaussianBlur stdDeviation="2.5" result="c"/><feMerge><feMergeNode in="c"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
                  </defs>

                  {/* edges */}
                  {EDGES.map((e,i)=>{
                    const a=byId.get(e.from), b=byId.get(e.to);
                    if(!a||!b) return null;
                    const isBlastEdge = !!(sel && blastSet.has(e.from) && blastSet.has(e.to));
                    const isHit = !!(sel && (e.from===sel || e.to===sel));
                    const animLevel = blastInfo?.levels.findIndex(l=> l.includes(e.to));
                    const visibleInPlay = !play || (animLevel!=null && animLevel>=0 && animLevel<=playStep);
                    if(play && sel && blastSet.has(e.to) && !visibleInPlay) return null;
                    const midX=(a.x+b.x)/2, midY=(a.y+b.y)/2 + (layoutMode==="hierarchical" ? 14 : -8);
                    const d = layoutMode==="hierarchical" ? `M${a.x} ${a.y+22} Q${midX} ${midY} ${b.x} ${b.y-18}` : `M${a.x} ${a.y+20} C${midX} ${a.y+18}, ${midX} ${b.y-18}, ${b.x} ${b.y-18}`;
                    const cls = isHit ? "edge hit" : isBlastEdge ? "edge blast" : "edge";
                    return (
                      <motion.path key={`${e.from}-${e.to}-${i}`} d={d} className={cls} markerEnd={isHit?"url(#arr-hit)": isBlastEdge?"url(#arr-blast)":"url(#arr)"}
                        style={{stroke: isHit ? "var(--red)" : isBlastEdge ? "var(--accent)" : "rgba(120,130,140,0.45)", strokeWidth: isHit?2.2: isBlastEdge?1.9:1.1, fill:"none", opacity: filteredIds.has(e.from)&&filteredIds.has(e.to)?1:0.18}}
                        initial={motionOK?{pathLength:0, opacity:0}:false} animate={{pathLength:1, opacity: filteredIds.has(e.from)&&filteredIds.has(e.to)? (isHit?1: isBlastEdge?0.95:0.55):0.12}} transition={{duration:0.45, delay: Math.min(i*0.008,0.35), ease:EASE}}
                      />
                    );
                  })}

                  {/* nodes */}
                  {NODES.map((n, idx)=>{
                    const isSel = sel===n.id;
                    const isBlast = blastSet.has(n.id);
                    const isUp = upstream.has(n.id);
                    const isHover = hover===n.id;
                    const isFaded = !filteredIds.has(n.id) || (!!sel && !isSel && !isBlast && !isUp && q==="" && kindFilter==="all");
                    const distLevel = blastInfo?.levels.findIndex(l=> l.includes(n.id));
                    if(play && sel && isBlast && distLevel!=null && distLevel>playStep) return null;
                    return (
                      <motion.g key={n.id} onClick={()=> setSel(isSel?null:n.id)} onMouseEnter={()=>setHover(n.id)} onMouseLeave={()=>setHover(null)}
                        initial={motionOK?{opacity:0, scale:0.9}:false} animate={{opacity:1, scale:1}} transition={{duration:0.22, delay: Math.min(idx*0.012,0.4), ease:EASE}}
                        style={{cursor:"pointer", transformOrigin:`${n.x}px ${n.y}px`}}
                      >
                        <rect x={n.x-78} y={n.y-2} width={156} height={44} rx={9}
                          fill={isSel?"color-mix(in srgb, var(--red) 10%, var(--panel))": isBlast?"color-mix(in srgb, var(--accent) 10%, var(--panel))": "var(--panel)"}
                          stroke={isSel? "var(--red)" : isHover? "var(--accent)": graphColor(n.kind)}
                          strokeWidth={isSel?2.2: isHover?1.6:1.3}
                          opacity={isFaded?0.28:1}
                          filter={isSel||isHover? "url(#glow)": undefined}
                        />
                        <rect x={n.x-78} y={n.y-2} width={156} height={4} rx={2} fill={graphColor(n.kind)} opacity={isFaded?0.2:0.9} style={{stroke:"none"}}/>
                        {/* degree dots */}
                        {(n.degreeIn + n.degreeOut)>0 && (
                          <text x={n.x+68} y={n.y+8} textAnchor="end" style={{fontSize:8.5, fill:"var(--faint)", fontFamily:"var(--mono)"}}>{n.degreeIn}→{n.degreeOut}</text>
                        )}
                        <text x={n.x} y={n.y+16} textAnchor="middle" style={{fontWeight:700, fontSize:11.5, fill: isSel? "var(--red)": isBlast?"var(--accent)":"var(--text)", fontFamily:"var(--mono)"}}>{n.label.length>20? n.label.slice(0,19)+"…": n.label}</text>
                        <text x={n.x} y={n.y+30} textAnchor="middle" style={{fontSize:9, fill:"var(--faint)", fontFamily:"var(--mono)", letterSpacing:.06}}>{KIND_ICON[n.kind.toLowerCase()] ?? "⬥"} {n.kind} {n.crit? `· ${n.crit}`:""}</text>
                        {isBlast && distLevel!=null && distLevel>0 && (
                          <g><circle cx={n.x+70} cy={n.y+34} r={9} fill="var(--accent)" opacity={0.95}/><text x={n.x+70} y={n.y+37} textAnchor="middle" style={{fontSize:9, fontWeight:800, fill:"var(--on-accent)"}}>{distLevel}</text></g>
                        )}
                        {(isUp || isBlast || isSel) && <circle cx={n.x} cy={n.y-5} r={3} fill={isSel?"var(--red)": isBlast?"var(--accent)":"var(--violet)"} opacity={0.9}/>}
                      </motion.g>
                    );
                  })}
                </svg>
              </div>

              {/* minimap */}
              {showMinimap && NODES.length>0 && (
                <div style={{position:"absolute", right:10, bottom:10, width:148, height:84, background:"var(--panel)", border:"1px solid var(--line)", borderRadius:"var(--r)", overflow:"hidden", boxShadow:"0 6px 20px rgba(0,0,0,0.35)"}}>
                  <div style={{fontSize:8, letterSpacing:.08, color:"var(--faint)", padding:"4px 6px", borderBottom:"1px solid var(--line)", display:"flex", justifyContent:"space-between"}}><span>MINIMAP{EDGES.length > 120 ? ` · first 120 of ${EDGES.length} edges` : ""}</span><span style={{color:"var(--dim)"}}>{Math.round(zoom*100)}%</span></div>
                  <svg viewBox="0 0 840 420" width="148" height={64} style={{display:"block", background:"var(--bg-2)"}}>
                    {EDGES.slice(0,120).map((e,i)=>{ const a=byId.get(e.from), b=byId.get(e.to); if(!a||!b) return null; return <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="var(--line-strong)" strokeWidth={0.8} opacity={0.5}/>})}
                    {NODES.map(n=> <circle key={n.id} cx={n.x} cy={n.y} r={3} fill={sel===n.id?"var(--red)": blastSet.has(n.id)?"var(--accent)": graphColor(n.kind)} stroke="var(--panel)" strokeWidth={0.6}/>)}
                    {/* viewport */}
                    <rect x={420 - 120/zoom} y={210 - 70/zoom} width={240/zoom} height={140/zoom} fill="none" stroke="var(--accent)" strokeWidth={1} strokeDasharray="4 3" rx={4}/>
                  </svg>
                </div>
              )}

              {filteredIds.size===0 && NODES.length>0 && (
                <div style={{position:"absolute", left:"50%", top:"50%", transform:"translate(-50%,-50%)", background:"var(--panel)", border:"1px solid var(--line)", borderRadius:"var(--r)", padding:"10px 14px", fontSize:12, color:"var(--dim)"}}>
                  No nodes match “{q}” in <b style={{color:"var(--text)"}}>{kindFilter}</b> — <button onClick={()=>{setQ(""); setKindFilter("all");}} style={{border:0, background:"none", color:"var(--accent)", cursor:"pointer", fontWeight:600}}>Clear filters</button>
                </div>
              )}
            </div>
          )}

          {showLegend && (
            <div style={{display:"flex", gap:8, flexWrap:"wrap", alignItems:"center", padding:"10px 12px", borderTop:"1px solid var(--line)", background:"var(--panel)", fontSize:11}}>
              <span style={{color:"var(--faint)", fontWeight:600, letterSpacing:.06}}>LEGEND</span>
              {Object.entries(KIND_COLOR).slice(0,8).map(([k,c])=>(
                <span key={k} style={{display:"inline-flex", alignItems:"center", gap:6, padding:"3px 8px", borderRadius:99, background:"var(--bg-2)", border:"1px solid var(--line)", color:"var(--dim)", textTransform:"capitalize"}}>
                  <span style={{width:10, height:10, borderRadius:2, background:c, display:"inline-block"}}/>{k}
                </span>
              ))}
              <span style={{display:"inline-flex", alignItems:"center", gap:6, padding:"3px 8px", borderRadius:99, background:"color-mix(in srgb, var(--red) 12%, var(--panel))", border:"1px solid var(--red)", color:"var(--red)"}}><span style={{width:8,height:8,borderRadius:99, background:"var(--red)"}}/>selected</span>
              <span style={{display:"inline-flex", alignItems:"center", gap:6, padding:"3px 8px", borderRadius:99, background:"color-mix(in srgb, var(--accent) 12%, var(--panel))", border:"1px solid var(--accent)", color:"var(--accent)"}}><span style={{width:8,height:8,borderRadius:99, background:"var(--accent)"}}/>blast ({blastSet.size})</span>
              <span style={{marginLeft:"auto", color:"var(--faint)", fontFamily:"var(--mono)", fontSize:10}}>drag = pan · wheel = zoom · click node = inspect</span>
            </div>
          )}
        </Panel>

        {/* Inspector */}
        <div style={{display:"flex", flexDirection:"column", gap:12, position:"sticky", top:12}}>
          <Panel title="" sub="" style={{padding:0, overflow:"hidden", borderTop:"2px solid var(--accent)"}}>
            <div style={{padding:"12px 14px", display:"flex", alignItems:"center", justifyContent:"space-between", borderBottom:"1px solid var(--line)", background:"var(--panel)"}}>
              <div style={{display:"flex", alignItems:"center", gap:8}}><IconTarget size={13} style={{color: sel?"var(--red)":"var(--dim)"}}/><span style={{fontSize:12, fontWeight:700}}>{sel? "Inspector — blast analysis" : "Inspector"}</span>{sel && <Badge tone="red">{blastSet.size} downstream</Badge>}</div>
              {sel && <button className="btn sm" onClick={()=>setSel(null)} style={{fontSize:11}}>✕ Clear</button>}
            </div>

            {!sel ? (
              <div style={{padding:16}}>
                <div style={{textAlign:"center", padding:"18px 12px", border:"1px dashed var(--line-strong)", borderRadius:"var(--r)", background:"var(--bg-2)"}}>
                  <div style={{fontSize:22}}>◎</div>
                  <div style={{fontWeight:700, marginTop:6}}>Select a node to inspect</div>
                  <div style={{fontSize:12, color:"var(--dim)", marginTop:6, lineHeight:1.5}}>See blast radius, upstream ancestors, provenance and hops. Use filters to narrow the canvas, then click through the topology.</div>
                </div>
                <div style={{marginTop:12, display:"grid", gridTemplateColumns:"1fr 1fr", gap:8}}>
                  <div style={{padding:"10px 12px", background:"var(--panel-2)", border:"1px solid var(--line)", borderRadius:"var(--r)"}}><div style={{fontSize:10, color:"var(--dim)", letterSpacing:.06}}>AVG DEGREE</div><div style={{fontSize:18, fontWeight:800, fontFamily:"var(--mono)"}}>{avgDeg}</div></div>
                  <div style={{padding:"10px 12px", background:"var(--panel-2)", border:"1px solid var(--line)", borderRadius:"var(--r)"}}><div style={{fontSize:10, color:"var(--dim)", letterSpacing:.06}}>MAX HOPS</div><div style={{fontSize:18, fontWeight:800}}>{hops}</div></div>
                </div>
                <div style={{marginTop:12, padding:"10px 12px", background:"var(--bg-2)", border:"1px solid var(--line)", borderRadius:"var(--r)", fontSize:11, color:"var(--dim)", lineHeight:1.5}}>
                  <b style={{color:"var(--text)"}}>Tip:</b> Use <b>Hierarchical</b> to read provider → consumer flow top-to-bottom. <b>Force</b> reveals clusters and bridges. Orphans are isolated — they indicate missing edges or standalone scopes.
                </div>
                <Link to="/what-if" className="btn sm" style={{marginTop:12, width:"100%", textAlign:"center", display:"block", textDecoration:"none"}}>Open What-If Simulator →</Link>
              </div>
            ) : (
              <div style={{padding:"12px 14px", display:"flex", flexDirection:"column", gap:12}}>
                {/* selected card */}
                <div style={{padding:"12px", background:"var(--bg-2)", border:"1px solid var(--line)", borderRadius:"var(--r)", borderLeft:`3px solid ${graphColor(selNode?.kind??"")}`}}>
                  <div style={{fontSize:10, color:"var(--dim)", letterSpacing:.08}}>SELECTED NODE</div>
                  <div style={{fontSize:15, fontWeight:800, fontFamily:"var(--mono)", margin:"4px 0 2px", wordBreak:"break-all"}}>{selNode?.label ?? sel}</div>
                  <div style={{display:"flex", gap:6, flexWrap:"wrap", alignItems:"center"}}>
                    <Badge tone={KIND_TONE[selNode?.kind??""]??""}>{(selNode?.kind??"node").toUpperCase()}</Badge>
                    <span style={{fontFamily:"var(--mono)", fontSize:11, color:"var(--dim)"}}>{selNode?.sub || sel}</span>
                    <button onClick={()=>navigator.clipboard.writeText(sel)} style={{marginLeft:"auto", fontSize:10, padding:"3px 8px", border:"1px solid var(--line)", borderRadius:"var(--r)", background:"var(--panel)", cursor:"pointer", color:"var(--dim)"}}>⧉ Copy ID</button>
                  </div>
                  <div style={{display:"flex", gap:8, marginTop:10}}>
                    <div style={{flex:1, padding:"8px 10px", background:"var(--panel)", border:"1px solid var(--line)", borderRadius:"var(--r)", textAlign:"center"}}><div style={{fontSize:10, color:"var(--dim)"}}>IN</div><div style={{fontWeight:800, fontSize:16}}>{selNode?.degreeIn??0}</div></div>
                    <div style={{flex:1, padding:"8px 10px", background:"var(--panel)", border:"1px solid var(--line)", borderRadius:"var(--r)", textAlign:"center"}}><div style={{fontSize:10, color:"var(--dim)"}}>OUT</div><div style={{fontWeight:800, fontSize:16}}>{selNode?.degreeOut??0}</div></div>
                    <div style={{flex:1, padding:"8px 10px", background:"color-mix(in srgb, var(--accent) 10%, var(--panel))", border:"1px solid var(--accent)", borderRadius:"var(--r)", textAlign:"center"}}><div style={{fontSize:10, color:"var(--dim)"}}>BLAST</div><div style={{fontWeight:800, fontSize:16, color:"var(--accent)"}}>{blastSet.size}</div></div>
                  </div>
                </div>

                {/* blast levels stepper */}
                {blastInfo && (
                  <div style={{padding:"10px 12px", background:"var(--panel-2)", border:"1px solid var(--line)", borderRadius:"var(--r)"}}>
                    <div style={{display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:8}}>
                      <span style={{fontSize:11, fontWeight:700, letterSpacing:.05}}>Blast propagation</span>
                      <span style={{fontSize:11, color:"var(--dim)"}}>{blastInfo.levels.length-1} hops max · {blastInfo.levels.flat().length} nodes</span>
                    </div>
                    <div style={{display:"flex", gap:6, flexWrap:"wrap", alignItems:"center"}}>
                      {blastInfo.levels.map((lvl, i)=>(
                        <React.Fragment key={i}>
                          {i>0 && <span style={{color:"var(--line-strong)"}}>→</span>}
                          <span style={{display:"inline-flex", alignItems:"center", gap:6, padding:"6px 10px", borderRadius:99, background: play ? (i<=playStep? "var(--accent)" : "var(--bg-2)") : i===0? "var(--panel)" : "var(--bg-2)", border:`1px solid ${i===0?"var(--accent)": i<=playStep&&play?"var(--accent)":"var(--line)"}`, color: play&&i<=playStep? "var(--on-accent)":"var(--text)", fontSize:11, fontWeight: i===0?700:500, opacity: play&&i>playStep?0.45:1}}>
                            <span style={{width:18, height:18, borderRadius:99, background: i===0? "var(--red)": "var(--line-strong)", color:"#fff", display:"grid", placeItems:"center", fontSize:10, fontWeight:800}}>{i}</span>
                            {i===0? "origin" : `${lvl.length} node${lvl.length!==1?"s":""}`}
                          </span>
                        </React.Fragment>
                      ))}
                    </div>
                    <div style={{marginTop:10}}><Bar value={blastSet.size? Math.min(1, blastSet.size/ Math.max(1,NODES.length)) :0} tone="amber" /></div>
                  </div>
                )}

                {/* downstream */}
                <div>
                  <div style={{fontSize:11, fontWeight:700, color:"var(--faint)", marginBottom:6}}>DOWNSTREAM ({blastSet.size})</div>
                  {blastSet.size===0 ? <div style={{fontSize:12, color:"var(--dim)", padding:"10px", background:"var(--bg-2)", borderRadius:"var(--r)", border:"1px solid var(--line)"}}>No downstream dependents — this node is a leaf. Safe to rotate without cascade, but verify via evidence.</div> : (
                    <div style={{maxHeight:160, overflow:"auto", display:"flex", flexDirection:"column", gap:4, paddingRight:2}}>
                      {Array.from(blastSet).slice(0,30).map(id=>{
                        const n=byId.get(id); const d=blastInfo?.dist.get(id)??0;
                        return <div key={id} onClick={()=>setSel(id)} style={{display:"flex", alignItems:"center", gap:8, padding:"7px 9px", background:"var(--panel-2)", border:"1px solid var(--line)", borderRadius:"var(--r)", cursor:"pointer", fontSize:12}}>
                          <span style={{width:18, height:18, borderRadius:99, background:"var(--accent)", color:"var(--on-accent)", display:"grid", placeItems:"center", fontSize:10, fontWeight:800}}>{d}</span>
                          <span style={{fontFamily:"var(--mono)", fontWeight:600, flex:1, whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis"}}>{n?.label ?? id}</span>
                          <Badge tone={KIND_TONE[n?.kind??""]??""}>{(n?.kind??"").slice(0,6).toUpperCase()}</Badge>
                        </div>;
                      })}
                      {blastSet.size>30 && <div style={{fontSize:11, color:"var(--faint)", textAlign:"center", padding:6}}>…and {blastSet.size-30} more — export graph JSON for full list</div>}
                    </div>
                  )}
                </div>

                <div>
                  <div style={{fontSize:11, fontWeight:700, color:"var(--faint)", marginBottom:6}}>UPSTREAM ({upstream.size})</div>
                  {upstream.size===0 ? <div style={{fontSize:12, color:"var(--dim)", padding:"8px 10px", background:"var(--bg-2)", borderRadius:"var(--r)", border:"1px solid var(--line)"}}>No ancestors — source node.</div> : (
                    <div style={{maxHeight:120, overflow:"auto", display:"flex", flexDirection:"column", gap:4}}>
                      {Array.from(upstream).slice(0,20).map(id=>{ const n=byId.get(id); return <div key={id} onClick={()=>setSel(id)} style={{padding:"6px 8px", background:"var(--panel-2)", border:"1px solid var(--line)", borderRadius:"var(--r)", fontSize:12, cursor:"pointer", display:"flex", justifyContent:"space-between"}}><span style={{fontFamily:"var(--mono)"}}>{n?.label ?? id}</span><Badge tone={KIND_TONE[n?.kind??""]??""}>{n?.kind??"—"}</Badge></div>; })}
                      {upstream.size>20 && <div style={{fontSize:11, color:"var(--faint)", textAlign:"center", padding:6}}>…and {upstream.size-20} more — export graph JSON for the full list</div>}
                    </div>
                  )}
                </div>

                <div style={{display:"flex", gap:8}}>
                  <Link to={`/what-if?seed=${encodeURIComponent(sel)}`} className="btn sm primary" style={{flex:1, textAlign:"center", textDecoration:"none"}}>What-if →</Link>
                  <button className="btn sm" onClick={()=>{ const data={seed: sel, blast: Array.from(blastSet), upstream: Array.from(upstream), levels: blastInfo?.levels}; const blob=new Blob([JSON.stringify(data,null,2)],{type:"application/json"}); const url=URL.createObjectURL(blob); const a=document.createElement("a"); a.href=url; a.download=`blast-${sel.slice(0,10)}.json`; a.click(); URL.revokeObjectURL(url);}} style={{flex:1}}>Export blast JSON</button>
                </div>
              </div>
            )}
          </Panel>

          {/* provenance micro */}
          <Panel title="Edge provenance" sub="how each link was learned — never assumed" style={{padding:"12px 14px"}}>
            <div style={{display:"flex", gap:8, flexWrap:"wrap"}}>
              {[
                ["Manual", EDGES.filter(e=> e.provenance.toLowerCase().includes("manual")).length, "slate"],
                ["Scanner", EDGES.filter(e=> e.provenance.toLowerCase().includes("scan")).length, "cyan"],
                ["Declared", EDGES.filter(e=> !e.provenance || e.provenance.toLowerCase().includes("unatt")).length, "violet"],
              ].map(([k,v,tone])=>(
                <div key={k as string} style={{flex:"1 1 90px", padding:"8px 10px", background:"var(--panel-2)", border:"1px solid var(--line)", borderRadius:"var(--r)", textAlign:"center"}}>
                  <div style={{fontSize:10, color:"var(--dim)", letterSpacing:.06}}>{k as string}</div>
                  <div style={{fontWeight:800, fontSize:16, color:`var(--${tone})`}}>{v as number}</div>
                </div>
              ))}
            </div>
            <div style={{fontSize:11, color:"var(--dim)", marginTop:8, lineHeight:1.5}}>Declared = operator statement · Scanner-derived = evidence-bound · Low density does not imply safety — it implies sparse discovery.</div>
          </Panel>
        </div>
      </div>

      <div className="grid cols-2 mt">
        <Panel title={sel ? `Blast table — ${byId.get(sel)?.label ?? sel}` : "Blast table"} sub={sel ? `rows are downstream of ${sel.slice(0,18)} — sorted by hops` : "select a node to populate"}>
          {sel ? <Table head={["#","node","kind","hops"]} rows={Array.from(blastSet).slice(0,40).map((id,i)=>{ const n=byId.get(id); const h=blastInfo?.dist.get(id)??0; return [i+1, <span className="mono" key="n">{n?.label ?? id}</span>, <Badge key="k" tone={KIND_TONE[n?.kind??""]??""}>{n?.kind??"—"}</Badge>, h]; })} /> : <div className="dim" style={{fontSize:13.5}}>Blast table appears after selection — provenance and hops included.</div>}
        </Panel>
        <Panel title="Impact summary" sub="evidence-linked impact of the current selection">
          {sel ? (
            <div style={{display:"flex", flexDirection:"column", gap:10}}>
              <div className="kpi"><span className="k">blast size</span><span className="v" style={{color:"var(--red)"}}>{blastSet.size}</span></div>
              <div className="kpi"><span className="k">upstream ancestors</span><span className="v">{upstream.size}</span></div>
              <div className="kpi"><span className="k">edge exposure</span><span className="v">{EDGES.filter(e=> blastSet.has(e.to)|| blastSet.has(e.from)).length}</span></div>
              <Link to="/what-if" className="btn sm" style={{alignSelf:"flex-start"}}>Run migration analysis →</Link>
            </div>
          ) : <div className="dim" style={{fontSize:13.5}}>Impact is computed from live downstream traversal (BFS, no inference). Select a node.</div>}
        </Panel>
      </div>
    </>
  );
}
