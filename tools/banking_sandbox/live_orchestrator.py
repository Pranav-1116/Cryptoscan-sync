"""Live orchestrator: sandbox runs fake hardware/network/crypto/vendors/software,
waits the configured interval after each synthetic change-and-scan pass, then monitors the next BOMs.

One command: python -m tools.banking_sandbox.cli live-orchestrator --estate /tmp/estate --output-root /tmp/live --port 8080
- Generates estate if missing
- After each completed pass, wait the configured interval before the next synthetic fixture change
- Writes change into estate/public/*, runs isolated scan (Landlock+seccomp), builds 6 BOMs, validates
- Dashboard polls /api/status every 2s, shows 6 BOM live counts, traffic feed, LB, hardware, network, validation
"""
from __future__ import annotations

import json
import random
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import urllib.parse

from tools.banking_sandbox.common import records, stream
# ensure PYTHONPATH for cbom/scanner/shared_models so live ticks work
import sys
ROOT = Path(__file__).resolve().parents[2]
for _p in [ROOT, ROOT/"services/cbom", ROOT/"services/scanner", ROOT/"shared/shared_models", ROOT/"services/network_scanner", ROOT/"services/vendor_intel"]:
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

# ---- LIVE DASHBOARD HTML ----------------------------------------------------

DASHBOARD_HTML = Path(__file__).parent / "live_orchestrator_dashboard.html"
# we inline to avoid extra file dependency
HTML = r"""<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>🔴 LIVE Sandbox → CryptoScan — All BOMs</title>
<style>
:root{color-scheme:dark;font:13px system-ui;background:#060b1a;color:#dbe6ff;--line:#1e2e4a;--card:#0d1730;--accent:#5af;--ok:#7ef0c2;--warn:#ffd36a;--bad:#ff8d8d}
*{box-sizing:border-box}body{margin:0}
.topbar{position:sticky;top:0;z-index:10;background:linear-gradient(90deg,#0a1930,#0d2a4a);border-bottom:1px solid var(--line);display:flex;flex-wrap:wrap;gap:10px;align-items:center;padding:10px 14px}
.pill{border:1px solid #2a3f5f;border-radius:999px;padding:6px 10px;font-size:12px;background:#0e1f3a}
.live{animation:pulse 1.2s infinite alternate}
@keyframes pulse{from{box-shadow:0 0 0 0 rgba(94,255,180,.4)}to{box-shadow:0 0 12px 4px rgba(94,255,180,.2)}}
.grid{display:grid;gap:10px;padding:12px;grid-template-columns:repeat(auto-fit,minmax(220px,1fr))}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}
.kpi b{font-size:20px;display:block;margin-top:4px}.kpi span{color:#9ab0d0;font-size:11px}
h2{margin:6px 0 8px;font-size:14px}
h3{margin:10px 0 6px;font-size:12px;color:#9ab0d0}
table{width:100%;border-collapse:collapse}td,th{padding:6px 8px;border-bottom:1px solid #1a2d4a;text-align:left;font-size:12px}th{color:#9ab0d0}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0a1429;border:1px solid var(--line);border-radius:8px;padding:10px;max-height:340px;overflow:auto;font-size:11px;line-height:1.5}
.feed{max-height:200px;overflow:auto}
.badge{padding:2px 7px;border-radius:999px;font-size:11px;border:1px solid #2a3f5f}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}
.bar{height:6px;background:#122040;border-radius:999px;overflow:hidden}.fill{height:100%;background:linear-gradient(90deg,#5af,#7ef0c2);transition:width .6s}
a{color:#7dd7ff}
.tabs{display:flex;gap:8px;padding:0 12px;flex-wrap:wrap}
.tabs button{border:1px solid var(--line);background:#0e1f3a;color:#dbe6ff;padding:8px 12px;border-radius:8px;cursor:pointer}
.tabs button.active{background:#1a2f5a}
.columns{display:grid;grid-template-columns:1fr 1fr;gap:10px;padding:0 12px}
@media(max-width:900px){.columns{grid-template-columns:1fr}}
</style></head><body>
<div class=topbar>
 <b style="font-size:14px">🔴 LIVE SANDBOX → CRYPTOSCAN</b>
 <span class="pill live" id=liveDot>● LIVE • tick <b id=tick>—</b> • <span id=wall>—</span>s • next pass after <span id=interval>5</span>s</span>
 <span class=pill>estate: <code id=estate>—</code></span>
 <span class=pill>output: <code id=output>—</code> • <a id=olink href="#">open</a></span>
 <span class=pill>interval <input id=intv type=range min=3 max=15 value=5 style="width:80px"> <span id=intvV>5</span>s <button onclick="post('/api/tick-now')">tick now</button> <button onclick="post('/api/pause')"><span id=pauseT>pause</span></button></span>
 <span class=pill>wall <span id=totalWall>—</span>s • scan <span id=scanWall>—</span>s • P/R <span id=pr>—</span></span>
 <a class=pill href="/" style="text-decoration:none">↻ refresh</a>
 <a class=pill href="/api/status" target=_blank>api</a>
 <a class=pill href="/lab" target=_blank>lab index.html</a>
 <a class=pill href="/realbanks" target=_blank>realbanks.html</a>
</div>

<div class=grid id=boms></div>

<div class=columns>
 <div class=card><h2>🚦 Synthetic fixture change feed</h2><div id=feed class=feed></div></div>
 <div class=card><h2>⚖️ LoadBalancer — configured fixture hops</h2><div id=lb></div><pre id=lbRaw></pre></div>
</div>

<div class=columns>
 <div class=card><h2>🖥️ Fake Hardware (HBOM) + Vendors (VBOM)</h2><div id=hw></div></div>
 <div class=card><h2>🌐 Fake Network (NBOM) + Software (SBOM/TechBOM)</h2><div id=net></div></div>
</div>

<div class=columns>
 <div class=card><h2>🔐 Fake Cryptography (CBOM) — scanner-observed</h2><div id=crypto></div></div>
 <div class=card><h2>✓ Validation — UNKNOWN≠SAFE</h2><div id=val></div><pre id=valRaw></pre></div>
</div>

<div class=card style="margin:12px"><h2>History — last 20 ticks (sparkline)</h2><canvas id=chart width=900 height=140 style="width:100%;background:#0a1429;border:1px solid var(--line);border-radius:8px"></canvas><pre id=history></pre></div>

<script>
const $=id=>document.getElementById(id);
let pause=false;
async function fetchStatus(){
 let r=await fetch('/api/status',{cache:'no-store'}); let j=await r.json();
 $('tick').textContent=j.tick; $('wall').textContent=(j.wall_seconds||0).toFixed(1); $('interval').textContent=j.interval;
 $('estate').textContent=j.estate||'—'; $('output').textContent=j.latest_output||'—';
 if(j.latest_output) $('olink').href='/output/'+j.tick+'/'; else $('olink').href='#';
 $('totalWall').textContent=(j.wall_seconds||0).toFixed(2); $('scanWall').textContent=(j.last_scan_wall||0).toFixed(2);
 $('pr').textContent=(j.last_precision!=null? j.last_precision.toFixed(3):'—')+'/'+(j.last_recall!=null? j.last_recall.toFixed(3):'—');
 $('intvV').textContent=j.interval; $('intv').value=j.interval;

 // BOM cards
 let b=j.last_boms||{}; let h=j.history||[]; $('boms').innerHTML=[
  ['CBOM','crypto findings (scanner-observed)',b.cbom,'SCANNER_OBSERVED'],
  ['TechBOM','unified tech inventory',b.techbom,'FIXTURE_DERIVED'],
  ['SBOM','CycloneDX 1.5 from TechBOM',b.sbom,'PROJECTION'],
  ['HBOM','synthetic hardware+f/w',b.hbom,'LAB-HW'],
  ['VBOM','vendor declared catalog',b.vbom,'VENDOR_DECLARED'],
  ['NBOM','network endpoints (unobserved)',b.nbom,'UNOBSERVED'],
  ['LB-NBOM','load-balancer hops',b['lb-nbom'],'CONTROLLED_TOPO'],
  ['LB evid.','live TLS hops if any',b.lbEvidence||'—','LIVE?'],
 ].map(([title,sub,val,prov])=>{
   let c= (val && typeof val==='object')? (val.components||val.component_count||val.total_components||val.devices||val.count||JSON.stringify(val).slice(0,40)): (val||'—');
   return `<div class=card><h3>${title}</h3><span style="color:#9ab0d0">${sub} • ${prov}</span><b style="font-size:18px">${c}</b><div class=bar><div class=fill style="width:${Math.min(100, 30+ (j.tick*7)%70)}%"></div></div></div>`
 }).join('');

 // feed
 $('feed').innerHTML=(j.feed||[]).slice(-18).reverse().map(e=>`<div style="padding:6px 0;border-bottom:1px solid #1a2d4a"><span class=badge>${e.kind}</span> <b>${e.msg}</b> <span style="color:#9ab0d0">${e.detail||''}</span> <span style="float:right;color:#7a8db0">${e.ts||''}</span></div>`).join('') || '<span style=color:#9ab0d0>waiting first tick…</span>';

 // LB
 let lb=j.lb_state||{}; $('lb').innerHTML=`<table><tr><th>bank</th><th>lb_id</th><th>role</th><th>termination</th><th>ciphers</th></tr>${(lb.hops||[]).slice(0,8).map(h=>`<tr><td>${h.bank_id||''}</td><td>${h.lb_id||h.hop_id||''}</td><td>${h.role||''}</td><td>${h.configured?.termination||h.termination||''}</td><td style="font-size:11px">${(h.supported?.ciphers||h.configured?.ciphers||[]).join(', ')}</td></tr>`).join('')}</table><div style="margin-top:6px;color:#9ab0d0">changes this tick: ${lb.changes||0} • total hops ${lb.total_hops||0}</div>`;
 $('lbRaw').textContent=JSON.stringify(lb,null,2);

 // HW+vendors
 let hw=j.hw_state||{}; $('hw').innerHTML=`<div>HSMs: <b>${hw.hsm_count||0}</b> • servers: <b>${hw.servers||0}</b> • tpm: <b>${hw.tpm||0}</b> • firmware drift: <b>${hw.fw_drift||0}</b></div><div>vendors: <b>${hw.vendors||0}</b> • vendor crypto rows: <b>${hw.vendor_crypto||0}</b> • PQC-marked: <b>${hw.pqc||0}</b></div><pre>${(hw.samples||[]).slice(0,3).map(x=>JSON.stringify(x).slice(0,200)).join('\n')}</pre>`;

 // network+software
 let ns=j.net_state||{}; $('net').innerHTML=`<div>endpoints: <b>${ns.endpoints||0}</b> • microservices: <b>${ns.microservices||0}</b> • DBs: <b>${ns.dbs||0}</b></div><div>SBOM comps: <b>${ns.sbom||0}</b> • TechBOM layers: <b>${ns.layers||0}</b> • cipher drift: <b>${ns.cipher_drift||0}</b></div>`;

 // crypto
 let cr=j.crypto_state||{}; $('crypto').innerHTML=`<div>algorithms observed: <b>${cr.algos||0}</b> • AES: <b>${cr.aes||0}</b> • RSA: <b>${cr.rsa||0}</b> • PQC: <b>${cr.pqc||0}</b> • weak: <b>${cr.weak||0}</b></div><div>files scanned: <b>${cr.files||0}</b> • failure_rate: <b>${cr.fail||0}</b> • boundary: <b>${cr.boundary||''}</b></div><div style="margin-top:6px">${(cr.top||[]).map(a=>`<span class=badge>${a}</span>`).join(' ')}</div>`;

 // validation
 let v=j.validation||{}; $('val').innerHTML=`<div>precision <b>${v.precision!=null?v.precision.toFixed(3):'—'}</b> • recall <b>${v.recall!=null?v.recall.toFixed(3):'—'}</b> • schema CBOM <b>${v.cbom||''}</b> • SBOM <b>${v.sbom||''}</b></div><div style="color:#9ab0d0">UNKNOWN=${v.unknown||0} • ${v.msg||''}</div>`;
 $('valRaw').textContent=JSON.stringify(v,null,2);

 // history
 $('history').textContent=(h.slice(-12).map(x=>`tick ${x.tick}: CBOM ${x.cbom||'?'} SBOM ${x.sbom||'?'} NBOM ${x.nbom||'?'} P ${x.p!=null?x.p.toFixed(2):'?' } R ${x.r!=null?x.r.toFixed(2):'?'}`).join('\n')||'—');
 drawChart(h);
}
function drawChart(h){
 let c=$('chart'), ctx=c.getContext('2d'); ctx.clearRect(0,0,c.width,c.height);
 if(!h.length) return;
 let max=Math.max(...h.map(x=>Math.max(x.cbom||0,x.sbom||0,x.nbom||0)),1);
 ctx.strokeStyle='#1e2e4a'; ctx.beginPath(); ctx.moveTo(30,c.height-20); ctx.lineTo(c.width-10,c.height-20); ctx.stroke();
 ['cbom','sbom','nbom'].forEach((k,col)=>{
   let colors={cbom:'#5af',sbom:'#7ef0c2',nbom:'#ffd36a'}; ctx.strokeStyle=colors[k]; ctx.beginPath();
   h.slice(-30).forEach((x,i)=>{ let v=x[k]||0, px=30+ i*(c.width-40)/Math.max(1,h.slice(-30).length-1), py=c.height-20 - (v/max)*(c.height-40); if(i===0) ctx.moveTo(px,py); else ctx.lineTo(px,py);}); ctx.stroke();
 });
 ctx.fillStyle='#9ab0d0'; ctx.fillText('CBOM',10,14); ctx.fillStyle='#5af'; ctx.fillRect(50,6,14,6);
 ctx.fillStyle='#9ab0d0'; ctx.fillText('SBOM',70,14); ctx.fillStyle='#7ef0c2'; ctx.fillRect(110,6,14,6);
 ctx.fillStyle='#9ab0d0'; ctx.fillText('NBOM',130,14); ctx.fillStyle='#ffd36a'; ctx.fillRect(170,6,14,6);
}
async function post(p,body){ await fetch(p,{method:'POST',body:body?JSON.stringify(body):null}); fetchStatus(); }
$('intv').addEventListener('change', e=> post('/api/interval',{interval: parseInt(e.target.value)}));
setInterval(fetchStatus, 2000); fetchStatus();
</script></body></html>
"""

# ---- MUTATORS ---------------------------------------------------------------

def _pick(arr, k=1):
    return random.sample(arr, min(k, len(arr)))

def mutate_network(estate: Path) -> dict:
    """Flip cipher/protocol on 1-2 random endpoints."""
    files = list((estate / "public/network").glob("*.jsonl"))
    if not files: return {"kind": "network", "msg": "no network fixtures", "events": 0}
    target = random.choice(files)
    rows = list(records(target))
    if not rows: return {"kind": "network", "msg": "empty", "events": 0}
    ciphers = ["AES-128-GCM","AES-256-GCM","CHACHA20-POLY1305","AES-128-CBC","DES-CBC"]
    protos = ["TLS1.2","TLS1.3"]
    n = random.randint(1,2)
    evts=[]
    for r in _pick(rows, n):
        oldp = r.get("simulated_negotiated_protocol")
        oldc = r.get("configured_cipher")
        r["simulated_negotiated_protocol"] = random.choice(protos)
        r["configured_cipher"] = random.choice(ciphers)
        r["last_traffic_at"] = datetime.now(timezone.utc).isoformat()
        r["traffic_mutation"] = "5s-auto-traffic"
        evts.append(f"{r.get('endpoint_id')} {oldp}/{oldc}→{r['simulated_negotiated_protocol']}/{r['configured_cipher']}")
    target.unlink()
    stream(target, rows)
    return {"kind": "TRAFFIC", "msg": f"network cipher flip x{n}", "detail": "; ".join(evts), "events": n, "cipher_drift": n}

def mutate_lb(estate: Path) -> dict:
    """Toggle LB termination mode / ciphers on one hop."""
    folders = [p for p in (estate / "public/load_balancers").glob("*") if p.is_dir()]
    if not folders: return {"kind": "lb", "msg": "no LB fixtures", "events": 0}
    folder = random.choice(folders)
    hops_p = folder / "hops.jsonl"
    cases_p = folder / "cases.jsonl"
    if not hops_p.exists(): return {"kind": "lb", "msg": "no hops", "events": 0}
    hops = list(records(hops_p))
    cases = list(records(cases_p)) if cases_p.exists() else []
    terms = ["termination","passthrough","re-encryption"]
    n = 1
    evts=[]
    for h in _pick(hops, n):
        old = h.get("configured",{}).get("termination") or h.get("termination") or "unknown"
        new_term = random.choice(terms)
        if "configured" in h:
            h["configured"]["termination"]=new_term
            h["configured"]["ciphers"]=random.sample(["ECDHE-RSA-AES128-GCM-SHA256","ECDHE-RSA-AES256-GCM-SHA384","TLS_AES_128_GCM_SHA256","CHACHA20-POLY1305"],2)
        else:
            h["termination"]=new_term
        h["last_traffic_at"]=datetime.now(timezone.utc).isoformat()
        h["traffic_mutation"]="5s-lb-toggle"
        evts.append(f"{h.get('hop_id')} {old}→{new_term}")
        # keep evidence in sync
        # also patch matching case listener if present
        for c in cases:
            if h.get("hop_id") in (c.get("hop_ids") or []):
                if "listener" in c:
                    c["listener"]["termination"]=new_term
    hops_p.unlink()
    stream(hops_p, hops)
    if cases:
        cases_p.unlink()
        stream(cases_p, cases)
    return {"kind": "LB", "msg": f"LB termination toggle x{n}", "detail": "; ".join(evts), "events": n}

def mutate_hardware(estate: Path) -> dict:
    files = list((estate / "public/hbom").glob("*.jsonl"))
    if not files: return {"kind":"hw","msg":"no hbom","events":0}
    f = random.choice(files)
    rows=list(records(f))
    if not rows: return {"kind":"hw","msg":"empty","events":0}
    n=random.randint(1,2)
    evts=[]
    for r in _pick(rows,n):
        old=r.get("firmware_version")
        newv=f"1.{random.randint(0,5)}.{random.randint(0,20)}-lab"
        r["firmware_version"]=newv
        r["last_firmware_check"]=datetime.now(timezone.utc).isoformat()
        r["traffic_mutation"]="5s-hw-rotate"
        evts.append(f"{r.get('asset_id')} fw {old}→{newv}")
    f.unlink()
    stream(f, rows)
    return {"kind":"HARDWARE","msg":f"hardware fw bump x{n}","detail":"; ".join(evts),"events":n}

def mutate_vendors(estate: Path) -> dict:
    files=list((estate/"public/vendors").glob("*.jsonl"))
    if not files: return {"kind":"vendor","msg":"no vendors","events":0}
    f=random.choice(files)
    rows=list(records(f))
    if not rows: return {"kind":"vendor","msg":"empty","events":0}
    n=1
    algos=["AES-256","RSA-2048","ECDSA-P256","ML-KEM-768","ChaCha20-Poly1305","HMAC-SHA256"]
    evts=[]
    for r in _pick(rows,n):
        old=r.get("declared_algorithms") or []
        new_algo=random.choice(algos)
        if new_algo not in old:
            old.append(new_algo)
        else:
            old=[a for a in old if a!=new_algo]
        r["declared_algorithms"]=old
        r["last_vendor_sync"]=datetime.now(timezone.utc).isoformat()
        evts.append(f"{r.get('vendor_id') or r.get('product')} algos → {old[-2:]}")
    f.unlink()
    stream(f, rows)
    return {"kind":"VENDOR","msg":f"vendor catalog flip x{n}","detail":"; ".join(evts),"events":n}

def mutate_crypto_software(estate: Path) -> dict:
    # touch applications source: bump a component version in techbom-derived? we mutate applications jsonl
    files=list((estate/"public/applications").glob("*.jsonl"))
    if not files: return {"kind":"software","msg":"no apps","events":0}
    f=random.choice(files)
    rows=list(records(f))
    if not rows: return {"kind":"software","msg":"empty","events":0}
    r=random.choice(rows)
    old=r.get("image_digest") or r.get("version") or "unknown"
    new=f"sha256:{random.randbytes(8).hex()}"
    r["image_digest"]=new
    r["last_build_at"]=datetime.now(timezone.utc).isoformat()
    f.unlink()
    stream(f, rows)
    return {"kind":"SOFTWARE","msg":"software image rotate","detail":f"{r.get('app_id')} {old[:12]}→{new[:12]}","events":1}

def refresh_manifest(estate: Path):
    """Recompute manifest.json after mutating public files so integrity passes."""
    from tools.banking_sandbox.common import file_hash
    import hashlib, json
    public = estate / "public"
    files = [
        {"path": str(p.relative_to(public)), "sha256": file_hash(p), "bytes": p.stat().st_size}
        for p in sorted(public.rglob("*")) if p.is_file()
    ]
    # preserve previous hash if exists
    prev = None
    mani_path = estate / "manifest.json"
    if mani_path.exists():
        try:
            prev = hashlib.sha256(mani_path.read_bytes()).hexdigest()
        except: pass
    obj = {"version": "SYNTHETIC_PUBLIC_MANIFEST_V1", "files": files, "synthetic": True}
    if prev:
        obj["previous_manifest_sha256"] = prev
    # original generator also writes generation-metrics style, but we keep required fields
    # write atomically
    tmp = mani_path.with_suffix(".tmp")
    tmp.write_bytes(json.dumps(obj, sort_keys=True, separators=(",",":")).encode() + b"\n")
    tmp.replace(mani_path)

def collect_snapshot(estate: Path) -> dict:
    """Quick counts for dashboard before scan."""
    # lightweight
    net_eps = sum(1 for f in (estate/"public/network").glob("*.jsonl") for _ in records(f))
    hw = sum(1 for f in (estate/"public/hbom").glob("*.jsonl") for _ in records(f))
    vend = sum(1 for f in (estate/"public/vendors").glob("*.jsonl") for _ in records(f))
    apps = sum(1 for f in (estate/"public/applications").glob("*.jsonl") for _ in records(f))
    lb_hops = sum(1 for f in (estate/"public/load_balancers").rglob("hops.jsonl") for _ in records(f))
    return {"net_endpoints": net_eps, "hw": hw, "vendors": vend, "apps": apps, "lb_hops": lb_hops}


# ---- ORCHESTRATOR -----------------------------------------------------------

class Orchestrator:
    def __init__(self, estate: Path, output_root: Path, port: int = 8080, interval: float = 5.0, banks: int = 4, profile: str = "worst-case-bank", host: str = "127.0.0.1"):
        if host != "127.0.0.1":
            raise ValueError("Live lab controls may listen on loopback only")
        if not 3 <= interval <= 15:
            raise ValueError("Live lab tick interval must be between 3 and 15 seconds")
        self.estate = Path(estate)
        self.output_root = Path(output_root)
        self.host = host
        self.port = port
        self.interval = interval
        self.banks = banks
        self.profile = profile
        self.state = {
            "estate": str(self.estate),
            "output_root": str(self.output_root),
            "port": port,
            "interval": interval,
            "tick": 0,
            "paused": False,
            "wall_seconds": 0,
            "start_ts": time.monotonic(),
            "feed": [],
            "history": [],
            "latest_output": None,
            "last_boms": {},
            "last_scan_wall": 0,
            "last_precision": None,
            "last_recall": None,
            "lb_state": {},
            "hw_state": {},
            "net_state": {},
            "crypto_state": {},
            "validation": {},
        }
        self._lock = threading.Lock()
        self._tick_lock = threading.Lock()
        self._t0 = time.monotonic()

    def _push_feed(self, entry):
        entry["ts"] = datetime.now(timezone.utc).strftime("%H:%M:%S")
        entry.setdefault("detail","")
        self.state["feed"].append(entry)
        if len(self.state["feed"])>80:
            self.state["feed"]=self.state["feed"][-80:]

    def ensure_estate(self):
        if not (self.estate/"LAB.json").exists():
            self.output_root.mkdir(parents=True, exist_ok=True)
            from tools.banking_sandbox.generator import generate
            self.estate.parent.mkdir(parents=True, exist_ok=True)
            print(f"[live-orchestrator] generating estate banks={self.banks} profile={self.profile} → {self.estate}", flush=True)
            generate(output=self.estate, banks=self.banks, profile=self.profile, seed="LIVE-ORCH-1")
            print("[live-orchestrator] estate ready", flush=True)
        else:
            print(f"[live-orchestrator] using existing estate {self.estate}", flush=True)
        self.output_root.mkdir(parents=True, exist_ok=True)

    def do_tick(self):
        if not self._tick_lock.acquire(blocking=False):
            return False
        try:
            return self._do_tick()
        finally:
            self._tick_lock.release()

    def _do_tick(self):
        with self._lock:
            tick = self.state["tick"] + 1
        out = self.output_root / f"tick-{tick:04d}"
        if out.exists() or out.is_symlink():
            with self._lock:
                self._push_feed({"kind": "ERROR", "msg": "tick output already exists; no files changed"})
            return False
        with self._lock:
            self.state["tick"] = tick
        print(f"\n[live] ===== TICK {tick} =====", flush=True)
        # 1. mutate 1-2 random subsystems (fake hardware/network/crypto/vendors/software + LB)
        mutators = [mutate_network, mutate_lb, mutate_hardware, mutate_vendors, mutate_crypto_software]
        picks = random.sample(mutators, k=random.randint(2,3))
        events = []
        for fn in picks:
            try:
                ev = fn(self.estate)
                events.append(ev)
                print(f"[live] mutation {ev}", flush=True)
                with self._lock:
                    self._push_feed({"kind": ev["kind"], "msg": ev["msg"], "detail": ev.get("detail","")})
            except Exception as e:
                print(f"[live] mutate {fn.__name__} failed: {e}", flush=True)

        # refresh manifest so integrity passes for connector
        try:
            refresh_manifest(self.estate)
        except Exception as e:
            print(f"[live] refresh_manifest failed: {e}", flush=True)

        # snapshot before scan
        snap = collect_snapshot(self.estate)

        # 2. run CryptoScan connector into tick output
        scan_wall = 0
        try:
            from tools.banking_sandbox.connector.connector import connect
            # _ensure_fresh requires not exists, so we pass new dir
            res = connect(self.estate, out)
            scan_wall = res.get("wall_seconds", 0)
            boms = res.get("boms", {})
            # also capture validation details
            import json as _j
            vpath = out / "reports/validation.json"
            vfull = _j.loads(vpath.read_text()) if vpath.exists() else {}
            # update state
            with self._lock:
                self.state["latest_output"] = str(out)
                self.state["last_boms"] = boms
                self.state["last_scan_wall"] = scan_wall
                self.state["last_precision"] = (vfull.get("static_accuracy") or {}).get("precision")
                self.state["last_recall"] = (vfull.get("static_accuracy") or {}).get("recall")
                self.state["wall_seconds"] = time.monotonic() - self._t0
                # enrich hw/net/lb
                # LB
                try:
                    lb_hops=[]
                    for f in (self.estate/"public/load_balancers").rglob("hops.jsonl"):
                        for r in records(f):
                            lb_hops.append(r)
                    self.state["lb_state"]={"total_hops": len(lb_hops), "hops": lb_hops[:6], "changes": sum(1 for e in events if e["kind"]=="LB")}
                except Exception: pass
                # HW/vendors
                try:
                    hw_rows=[]; vendors=[]
                    for f in (self.estate/"public/hbom").glob("*.jsonl"):
                        for r in records(f): hw_rows.append(r)
                    for f in (self.estate/"public/vendors").glob("*.jsonl"):
                        for r in records(f): vendors.append(r)
                    self.state["hw_state"]={
                        "hsm_count": len([r for r in hw_rows if "hsm" in str(r.get("kind","")).lower()]),
                        "servers": len([r for r in hw_rows if "server" in str(r.get("kind","")).lower()]),
                        "tpm": len([r for r in hw_rows if "tpm" in str(r.get("kind","")).lower()]),
                        "fw_drift": sum(1 for e in events if e["kind"]=="HARDWARE"),
                        "vendors": len(vendors),
                        "vendor_crypto": sum(len(r.get("declared_algorithms") or []) for r in vendors),
                        "pqc": sum(1 for r in vendors for a in (r.get("declared_algorithms") or []) if "ML-" in a),
                        "samples": hw_rows[:2]
                    }
                except Exception: pass
                # net/software
                try:
                    sbom = boms.get("sbom",{}).get("components") if isinstance(boms.get("sbom"), dict) else None
                    self.state["net_state"]={
                        "endpoints": snap["net_endpoints"],
                        "microservices": len([f for f in (self.estate/"public/applications").glob("*.jsonl")]),
                        "dbs": 0,
                        "sbom": sbom,
                        "layers": (boms.get("techbom",{}) or {}).get("layers") if isinstance(boms.get("techbom"), dict) else None,
                        "cipher_drift": sum(1 for e in events if e["kind"]=="TRAFFIC")
                    }
                except Exception: pass
                # crypto
                try:
                    # top algos from boms cbom
                    cbom_p = out/"boms/cbom.json"
                    algos=[]
                    if cbom_p.exists():
                        import json as __j
                        doc=__j.loads(cbom_p.read_text())
                        algos=[c.get("name") or c.get("cryptoProperties",{}).get("algorithm") or c.get("bom-ref") for c in (doc.get("components") or [])[:8]]
                    self.state["crypto_state"]={
                        "algos": len(algos),
                        "aes": len([a for a in algos if a and "AES" in a]),
                        "rsa": len([a for a in algos if a and "RSA" in a]),
                        "pqc": len([a for a in algos if a and "ML-" in a]),
                        "weak": len([a for a in algos if a and a in ("MD5","SHA-1","DES","RC4")]),
                        "files": (res.get("static_metrics") or {}).get("files") or (boms.get("static_metrics",{}).get("files") if isinstance(boms.get("static_metrics"), dict) else 0) or 0,
                        "fail": (res.get("static_metrics") or {}).get("failure_rate") or 0,
                        "boundary": str((res.get("static_metrics") or {}).get("boundary_receipt",{}).get("guard",{}).get("seccomp") or ""),
                        "top": algos[:5]
                    }
                except Exception as e:
                    print(f"crypto_state err {e}")
                # validation
                try:
                    sa=vfull.get("static_accuracy") or {}
                    self.state["validation"]={
                        "precision": sa.get("precision"),
                        "recall": sa.get("recall"),
                        "unknown": sa.get("unknown") or 0,
                        "msg": sa.get("note") or sa.get("scope") or "",
                        "cbom": str(vfull.get("schema_checks",{}).get("cbom",{}).get("ok")),
                        "sbom": str(vfull.get("schema_checks",{}).get("sbom",{}).get("ok")),
                    }
                except Exception: pass
                # history
                h_entry={
                    "tick": tick,
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "cbom": (boms.get("cbom",{}) or {}).get("components") if isinstance(boms.get("cbom"), dict) else 0,
                    "sbom": (boms.get("sbom",{}) or {}).get("components") if isinstance(boms.get("sbom"), dict) else 0,
                    "nbom": (boms.get("nbom", {}) or {}).get("components", 0),
                    "p": self.state["last_precision"],
                    "r": self.state["last_recall"],
                    "wall": scan_wall,
                }
                self.state["history"].append(h_entry)
                if len(self.state["history"])>60: self.state["history"]=self.state["history"][-60:]
                self._push_feed({"kind":"BOMS","msg":f"CBOM {h_entry['cbom']} SBOM {h_entry['sbom']} NBOM {h_entry['nbom']} P/R {h_entry['p']}/{h_entry['r']}", "detail": f"wall {scan_wall:.1f}s"})
                # update latest symlink
                latest = self.output_root / "latest"
                try:
                    if latest.is_symlink() or latest.exists():
                        latest.unlink()
                    latest.symlink_to(out.name)
                except Exception: pass
            print(f"[live] tick {tick} boms {boms} wall {scan_wall:.2f}s latest {out}", flush=True)
        except Exception as e:
            print(f"[live] connect failed tick {tick}: {e}", flush=True)
            import traceback; traceback.print_exc()
            with self._lock:
                self._push_feed({"kind":"ERROR","msg": f"connect failed: {type(e).__name__}", "detail": str(e)[:300]})
                self.state["wall_seconds"]=time.monotonic()-self._t0
        # ensure wall updated
        with self._lock:
            self.state["wall_seconds"]=time.monotonic()-self._t0

    def loop(self):
        self.ensure_estate()
        # initial tick immediately
        self.do_tick()
        while True:
            # Only unpaused time counts, and interval changes apply to this wait.
            elapsed = 0.0
            step = 0.2
            while True:
                time.sleep(step)
                with self._lock:
                    if self.state["paused"]:
                        continue
                    elapsed += step
                    interval = self.state["interval"]
                if elapsed >= interval:
                    break
            self.do_tick()

    def start_http(self):
        estate = self.estate
        output_root = self.output_root
        state_ref = self.state
        lock = self._lock

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                p = parsed.path
                if p in ("/","/index.html"):
                    self.send_response(200); self.send_header("Content-Type","text/html"); self.end_headers()
                    self.wfile.write(HTML.encode())
                    return
                if p == "/api/status":
                    with lock:
                        body=json.dumps(state_ref, indent=2).encode()
                    self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Cache-Control","no-store")
                    self.send_header("Access-Control-Allow-Origin","*")
                    self.end_headers(); self.wfile.write(body); return
                if p == "/api/history":
                    with lock:
                        body=json.dumps(state_ref.get("history",[]), indent=2).encode()
                    self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers(); self.wfile.write(body); return
                if p.startswith("/output/"):
                    # serve tick output files: /output/<tick>/... -> output_root/tick-*/...
                    parts = p[len("/output/"):].strip("/").split("/")
                    tick = parts[0] if parts else ""
                    # allow "latest" symlink
                    base = output_root / tick if tick else output_root
                    # if tick is numeric tick id (e.g., "3"), map to tick-0003
                    if tick.isdigit():
                        base = output_root / f"tick-{int(tick):04d}"
                    if tick == "latest":
                        base = output_root / "latest"
                    rel = "/".join(parts[1:]) if len(parts)>1 else ""
                    target = (base / rel).resolve() if rel else base.resolve()
                    # security: must be under output_root
                    try:
                        output_root_res = output_root.resolve()
                        if not target.is_relative_to(output_root_res):
                            self.send_error(403); return
                    except Exception:
                        self.send_error(404); return
                    if target.is_dir():
                        # list
                        self.send_response(200); self.send_header("Content-Type","text/html"); self.end_headers()
                        items = sorted(target.iterdir())
                        html = f"<h1>{p}</h1><ul>" + "".join(f"<li><a href='/output/{tick}/{x.name}'>{x.name}</a></li>" for x in items) + "</ul>"
                        self.wfile.write(html.encode()); return
                    if target.is_file():
                        self.send_response(200)
                        # guess content type
                        if target.suffix==".json": self.send_header("Content-Type","application/json")
                        elif target.suffix==".html": self.send_header("Content-Type","text/html")
                        self.send_header("Cache-Control","no-store")
                        self.end_headers(); self.wfile.write(target.read_bytes()); return
                    self.send_error(404); return
                if p in ("/lab","/lab/"):
                    # serve estate public lab dashboard
                    pub = estate / "public/index.html"
                    if pub.exists():
                        self.send_response(200); self.send_header("Content-Type","text/html"); self.end_headers()
                        self.wfile.write(pub.read_bytes()); return
                    self.send_error(404); return
                if p in ("/realbanks","/realbanks/","/realbanks.html"):
                    pub = estate / "public/realbanks.html"
                    if pub.exists():
                        self.send_response(200); self.send_header("Content-Type","text/html"); self.end_headers()
                        self.wfile.write(pub.read_bytes()); return
                    self.send_error(404); return
                if p.startswith("/lab/") or p.startswith("/realbanks/"):
                    # serve static public files
                    rel = p[len("/lab/"):] if p.startswith("/lab/") else p[len("/realbanks/"):]
                    target = (estate / "public" / rel).resolve()
                    estate_pub = (estate / "public").resolve()
                    if not target.is_relative_to(estate_pub) or not target.exists():
                        self.send_error(404); return
                    self.send_response(200)
                    if target.suffix==".json": self.send_header("Content-Type","application/json")
                    elif target.suffix==".html": self.send_header("Content-Type","text/html")
                    self.end_headers(); self.wfile.write(target.read_bytes()); return
                self.send_error(404)
            def do_POST(self):
                expected_origin = f"http://{self.server.server_address[0]}:{self.server.server_address[1]}"
                if self.headers.get("Origin") not in (None, expected_origin):
                    self.send_error(403, "Cross-origin lab controls refused"); return
                parsed = urllib.parse.urlparse(self.path)
                p=parsed.path
                try:
                    length = int(self.headers.get('Content-Length', 0) or 0)
                except ValueError:
                    self.send_error(400, "Invalid body length"); return
                if length < 0 or length > 4096:
                    self.send_error(413, "Lab control body exceeds limit"); return
                body = self.rfile.read(length) if length else b""
                try:
                    data = json.loads(body) if body else {}
                except ValueError:
                    self.send_error(400, "Invalid JSON"); return
                if not isinstance(data, dict):
                    self.send_error(400, "Object body required"); return
                if p=="/api/interval":
                    try:
                        iv = int(data.get("interval", 5))
                    except (ValueError, TypeError):
                        self.send_error(400, "Invalid interval"); return
                    iv=max(3,min(15,iv))
                    with lock: state_ref["interval"]=iv
                    self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers()
                    self.wfile.write(json.dumps({"interval":iv}).encode()); return
                if p=="/api/tick-now":
                    if self.server.orch._tick_lock.locked():
                        self.send_error(409, "A lab tick is already running"); return
                    threading.Thread(target=self.server.orch.do_tick, daemon=True).start()
                    self.send_response(202); self.end_headers(); self.wfile.write(b"accepted"); return
                if p=="/api/pause":
                    with lock: state_ref["paused"]=not state_ref["paused"]
                    self.send_response(200); self.end_headers(); self.wfile.write(b"ok"); return
                self.send_error(404)

        server = ThreadingHTTPServer((self.host, self.port), Handler)
        server.orch = self  # type: ignore
        print(f"[live] dashboard http://{self.host}:{self.port}/ → estate {estate} output {output_root}", flush=True)
        # also serve estate public directly for convenience?
        server.serve_forever()

def run_orchestrator(estate: Path, output_root: Path, port: int = 8080, interval: float = 5.0, banks: int = 4, profile: str = "worst-case-bank", host: str = "127.0.0.1"):
    orch = Orchestrator(estate=estate, output_root=output_root, port=port, interval=interval, banks=banks, profile=profile, host=host)
    # http in daemon thread
    t_http = threading.Thread(target=orch.start_http, daemon=True)
    t_http.start()
    # loop in main thread
    orch.loop()

