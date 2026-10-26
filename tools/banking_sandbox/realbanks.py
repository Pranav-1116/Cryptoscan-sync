"""Synthetic customer-look sandbox, separate from the lab's dark theme.

Static, same-origin, public-only. Balances and transactions are deterministic
fixtures, not customer accounts or bank operating claims.
"""

from pathlib import Path

HTML_REALBANKS = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Synthetic Banking Preview</title>
<style>
*{box-sizing:border-box}
:root{--nav:#0a2540;--nav2:#123058;--accent:#635bff;--accent2:#00d4ff;--bg:#f6f8fb;--card:#fff;--line:#e6e8f0;--text:#0a2540;--muted:#5b6b85;--ok:#00b67a;--warn:#ff8f00}
body{margin:0;font:14px 'Inter',system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text)}
a{color:inherit;text-decoration:none}
.topbar{position:sticky;top:0;z-index:20;background:var(--nav);color:#fff;display:flex;align-items:center;justify-content:space-between;padding:10px 18px;gap:12px;box-shadow:0 2px 12px rgba(10,37,64,.22)}
.brand{display:flex;align-items:center;gap:10px;font-weight:800;letter-spacing:.2px}
.logo{width:34px;height:34px;border-radius:9px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:grid;place-items:center;font-weight:900}
.topnav{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
.topnav a{opacity:.9;padding:8px 10px;border-radius:8px}
.topnav a.active{background:rgba(255,255,255,.12);opacity:1}
.pill{border:1px solid rgba(255,255,255,.22);padding:6px 10px;border-radius:999px;font-size:12px;color:#dbe6ff}
.wrap{display:grid;grid-template-columns:260px 1fr;min-height:calc(100vh - 54px)}
aside{background:#fff;border-right:1px solid var(--line);padding:18px;position:sticky;top:54px;height:calc(100vh - 54px);overflow:auto}
.side-head{font-size:11px;letter-spacing:.12em;color:var(--muted);margin:18px 0 8px;text-transform:uppercase}
.side a{display:flex;align-items:center;gap:10px;padding:10px 10px;border-radius:10px;color:var(--text);margin:2px 0}
.side a.active{background:#eef2ff;color:#2a3cff;font-weight:600}
.side a:hover{background:#f2f4f9}
.badge{margin-left:auto;background:#eef2ff;color:#3b5bdb;border-radius:999px;padding:2px 8px;font-size:11px}
main{padding:18px 18px 28px;max-width:1400px;width:100%}
.hero{background:linear-gradient(135deg,#0a2540 0%,#243b8d 55%,#635bff 100%);color:#fff;border-radius:18px;padding:20px 18px;display:flex;flex-wrap:wrap;gap:16px;align-items:center;justify-content:space-between;box-shadow:0 10px 30px rgba(10,37,64,.22)}
.hero h1{margin:0;font-size:22px}
.hero p{margin:6px 0 0;opacity:.88}
.select{appearance:none;background:#fff;border:1px solid var(--line);border-radius:10px;padding:10px 12px;min-width:260px}
.grid4{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:14px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:14px 14px;box-shadow:0 6px 16px rgba(10,37,64,.06)}
.kicker{font-size:11px;letter-spacing:.08em;color:var(--muted);text-transform:uppercase}
.card b{display:block;font-size:22px;margin:8px 0 6px}
.card small{color:var(--muted)}
.accent{height:4px;border-radius:999px;background:linear-gradient(90deg,var(--accent),var(--accent2));margin:10px -14px -14px}
.row2{display:grid;grid-template-columns:1.45fr .95fr;gap:14px}
.table{width:100%;border-collapse:collapse}
.table th{font-size:11px;letter-spacing:.08em;color:var(--muted);text-transform:uppercase;text-align:left;padding:10px 10px;border-bottom:1px solid var(--line)}
.table td{padding:11px 10px;border-bottom:1px solid #eef2f2;font-size:13px}
.chip{padding:4px 8px;border-radius:999px;font-size:11px;border:1px solid var(--line);background:#fff}
.chip.ok{background:#e6faf3;border-color:#bfe9d8;color:#0a7a4b}
.chip.warn{background:#fff3e0;border-color:#ffd8a6}
.muted{color:var(--muted)}
.utility{display:flex;gap:10px;flex-wrap:wrap;margin:10px 0}
.btn{border:1px solid var(--line);background:#fff;border-radius:10px;padding:10px 14px;font-weight:600}
.btn.primary{background:var(--nav);color:#fff;border-color:var(--nav)}
.branches{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.map{height:180px;border-radius:12px;background:linear-gradient(180deg,#e8eefc,#f6f8fb);border:1px solid var(--line);display:grid;place-items:center;color:var(--muted)}
.foot{margin-top:14px;padding:14px;background:#fff;border:1px solid var(--line);border-radius:12px;color:var(--muted);font-size:12px;line-height:1.6}
@media(max-width:1050px){.wrap{grid-template-columns:1fr}aside{display:none}.grid4{grid-template-columns:repeat(2,1fr)}.row2{grid-template-columns:1fr}.branches{grid-template-columns:1fr}}
</style></head><body>
<div class="topbar">
  <div class="brand"><div class="logo">LAB</div><div>Banking Sandbox<br><span style="font-weight:400;opacity:.8;font-size:11px">Synthetic fixtures • No customer accounts</span></div></div>
  <nav class="topnav">
    <a class="active" href="#">Accounts</a><a href="#">Payments</a><a href="#">Cards</a><a href="#">Loans</a><a href="#">Invest</a><a href="#">Support</a>
    <span class="pill">EN • Help • Sign out</span>
  </nav>
</div>
<div class="wrap">
  <aside class="side">
    <div class="kicker">Sandbox customer view</div>
    <a class="active" href="#">🏦 &nbsp; Overview <span class="badge" id="bankCount">—</span></a>
    <a href="#">💳 &nbsp; Accounts & cards</a>
    <a href="#">↗ &nbsp; Move money</a>
    <a href="#">📄 &nbsp; Statements</a>
    <a href="#">🏦 &nbsp; Branches & ATMs</a>
    <a href="#">🛡️ &nbsp; Security</a>
    <div class="side-head">Switch bank (sandbox estate)</div>
    <select id="bank" class="select"></select>
    <div style="margin-top:12px" class="muted">Public fixtures only — <code>catalog.json</code> + <code>banks/*.json</code></div>
    <div class="side-head">Data centers</div>
    <div id="dcList" class="muted"></div>
    <div class="side-head">Need help?</div>
    <div class="card" style="padding:12px">No customer support service<br><span class="muted">Sandbox demonstration only</span></div>
    <div style="margin-top:12px"><a href="./" style="color:var(--muted)">← Lab dashboard (index.html)</a> &nbsp; <a href="./realbanks.html" style="color:var(--muted)">Real-bank view</a></div>
  </aside>
  <main>
    <div class="hero">
      <div>
        <div style="opacity:.9;font-size:11px;letter-spacing:.1em;text-transform:uppercase">Welcome back</div>
        <h1 id="welcome">Good morning, Alex — here's your money</h1>
        <p id="subtitle">Synthetic lab • No deposit-insurance claim</p>
      </div>
      <div style="display:flex;gap:10px;align-items:center">
        <select id="bank2" class="select"></select>
        <button class="btn primary">New transfer</button>
      </div>
    </div>

    <div class="grid4" id="acctCards"></div>

    <div class="utility">
      <button class="btn">Pay bills</button><button class="btn">Deposit check</button><button class="btn">Wire transfer</button><button class="btn">Exchange</button>
      <span class="pill" style="background:#fff;color:var(--muted);border-color:var(--line)">🔒 Secure session • Last login <span id="lastLogin">today 08:42</span></span>
    </div>

    <div class="row2">
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center"><b>Recent transactions</b><span class="chip">Last 10 • <span id="txBank">—</span></span></div>
        <table class="table"><thead><tr><th>Date</th><th>Description</th><th>Category</th><th style="text-align:right">Amount</th></tr></thead><tbody id="txBody"></tbody></table>
      </div>
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center"><b>Spending this month</b><span class="chip ok">On track</span></div>
        <div style="height:120px;display:flex;align-items:end;gap:6px;padding:12px 0" id="bars"></div>
        <div class="muted" style="font-size:12px">Derived from sandbox fixtures — not real spend.</div>
        <div style="margin-top:10px"><b>Cards</b></div>
        <div id="cards" style="display:grid;gap:10px;margin-top:8px"></div>
      </div>
    </div>

    <div style="margin-top:14px" class="card">
      <div style="display:flex;justify-content:space-between;align-items:center"><b>Branch network</b><span class="chip">2 data centers • <span id="dcCount">—</span></span></div>
      <div class="branches" style="margin-top:10px">
        <div class="card" style="margin:0"><div class="kicker" id="dcA">DC-A</div><div class="map">🗺️ Map preview</div><div style="margin-top:8px" class="muted" id="dcAInfo"></div></div>
        <div class="card" style="margin:0"><div class="kicker" id="dcB">DC-B</div><div class="map">🗺️ Map preview</div><div style="margin-top:8px" class="muted" id="dcBInfo"></div></div>
        <div class="card" style="margin:0"><div class="kicker">Security</div><div style="font-size:12px;line-height:1.7" class="muted">Fixture security metadata • No live bank controls verified<br><span id="secLine">—</span></div><div class="accent"></div></div>
      </div>
    </div>

    <div class="foot">This sandbox renders <b>public fixtures</b> as a realistic banking experience. Account numbers, balances and transactions are <b>deterministic synthetic data</b> for the selected bank — not real customer data. No external scripts/trackers. Ground truth (<code>control/ground_truth</code>) is never served.</div>
  </main>
</div>
<script>
'use strict';
const $=id=>document.getElementById(id);
async function j(p){let r=await fetch(p,{cache:'no-store'}); if(!r.ok) throw Error(p); return r.json()}
async function lines(p){let r=await fetch(p,{cache:'no-store'}); if(!r.ok) throw Error(p); return (await r.text()).split('\n').filter(Boolean).map(x=>JSON.parse(x))}
function h(s){return s.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
function fmtUSD(n){return n<0? '-$'+Math.abs(n).toLocaleString(): '$'+n.toLocaleString()}
function seedNum(seed){let t=0; for(let i=0;i<seed.length;i++) t=(t*131+seed.charCodeAt(i))>>>0; return t}
function pick(arr, n, seed){let out=[]; for(let i=0;i<n;i++) out.push(arr[(seedNum(seed+':'+i))%arr.length]); return out}

let catalog=null;
let bankId=null;
const realNames=['Global Trust Bank','Horizon Financial','Metro Commercial Bank','Northfield Private Bank','Crestwood Savings','Atlas Union Bank','Beacon Hill Trust','Harborview National','Sterling Premier Bank','Summit Regional'];
const acctTemplates=[
  {name:'Everyday Checking', no:'• 4821', grad:'linear-gradient(135deg,#0a2540,#3b5bdb)'},
  {name:'High-Yield Savings', no:'• 9073', grad:'linear-gradient(135deg,#064e3b,#10b981)'},
  {name:'Travel Rewards Credit', no:'• 1104', grad:'linear-gradient(135deg,#4f46e5,#06b6d4)'},
  {name:'Investment Portfolio', no:'• 5519', grad:'linear-gradient(135deg,#7c3aed,#ec4899)'},
];
const merchants=[
  ['Starbucks','Dining'],['Whole Foods','Groceries'],['Shell','Transport'],['Netflix','Entertainment'],['United Airlines','Travel'],['CVS Pharmacy','Health'],['Zelle transfer to Maya','Transfer'],['Payroll deposit','Income'],['Rent • Midtown','Housing'],['Con Edison','Utilities']
];

async function load(){
  catalog=await j('catalog.json');
  if(!catalog.banks || !catalog.banks.length) throw Error('catalog empty');
  let opts=catalog.banks.map((b,i)=>[b.bank_id, (realNames[i%realNames.length]) + ' — ' + b.bank_id]);
  let s=$('bank'); let s2=$('bank2'); s.replaceChildren(); s2.replaceChildren();
  for(let [v,t] of opts){let o=document.createElement('option'); o.value=v; o.textContent=t; s.append(o); let o2=o.cloneNode(true); s2.append(o2)}
  $('bankCount').textContent=catalog.banks.length+' banks';
  bankId=catalog.banks[0].bank_id;
  $('bank').value=bankId; $('bank2').value=bankId;
  await render();
  $('bank').onchange=e=>{bankId=e.target.value; $('bank2').value=bankId; render().catch(err)}
  $('bank2').onchange=e=>{bankId=e.target.value; $('bank').value=bankId; render().catch(err)}
}
async function render(){
  let b=bankId;
  // public data — systems, applications, techbom for counts
  let [systems, apps, techbom] = await Promise.all([
    lines('systems/'+b+'.jsonl').catch(()=>[]),
    lines('applications/'+b+'.jsonl').catch(()=>[]),
    lines('techbom/'+b+'.jsonl').catch(()=>[])
  ]);
  let dcs=[...new Set(systems.map(s=>s.data_center))];
  $('dcList').textContent=dcs.join(' • ') || '—';
  $('dcCount').textContent=dcs.length+'';
  $('dcA').textContent=dcs[0]||'DC-A';
  $('dcB').textContent=dcs[1]||dcs[0]||'DC-B';
  $('dcAInfo').textContent=(systems.filter(s=>s.data_center===dcs[0]).length||0)+' systems • '+(apps.filter(a=> (a.system_id||'').includes(dcs[0].split('-').pop()) ).length||apps.length/2|0)+' apps';
  $('dcBInfo').textContent=(systems.filter(s=>s.data_center===dcs[1]).length||0)+' systems • '+(apps.filter(a=> ! (a.system_id||'').includes(dcs[0]?.split('-').pop()||'') ).length||apps.length/2|0)+' apps';
  // welcome
  let idx=seedNum(b)%realNames.length;
  $('welcome').textContent='Good morning, Alex — '+realNames[idx]+'  •  '+b;
  $('subtitle').textContent=(systems.length)+' systems • '+(apps.length)+' applications • synthetic fixtures, not insured accounts';
  $('txBank').textContent=b;
  $('lastLogin').textContent=new Date().toLocaleDateString()+' 08:42';
  $('secLine').textContent= dcs.length+' fixture data centers • '+systems.length+' systems • '+techbom.length+' components • protocol use unverified';

  // balances derived deterministically from bank
  let seed=seedNum(b);
  let balances=acctTemplates.map((t,i)=>{
    let base= 8000 + (seedNum(b+':bal'+i)%90000);
    if(i===1) base*=2; if(i===3) base*=3;
    return {...t, bal: base + (seed%100)/100}
  });
  $('acctCards').innerHTML=balances.map(a=>`
    <div class="card" style="position:relative;overflow:hidden">
      <div class="kicker">${h(a.name)} &nbsp; <span class="chip">${h(a.no)}</span></div>
      <b>${fmtUSD(a.bal)}</b>
      <small>Available • Updated just now</small>
      <div style="margin-top:10px;display:flex;gap:8px"><span class="chip">Statements</span><span class="chip">Move money</span></div>
      <div class="accent" style="background:${a.grad}"></div>
    </div>`).join('');

  // transactions
  let txs=[];
  for(let i=0;i<10;i++){
    let [m,cat]=merchants[(seed+i*7)%merchants.length];
    let amt = (seedNum(b+':tx'+i)%5000)/100;
    if(cat==='Income') amt*=-1* (20 + (seed+i)%30);
    else amt = amt * (i%4===0? -1:1);
    let d=new Date(); d.setDate(d.getDate()-i);
    txs.push({date: d.toLocaleDateString(), desc: m, cat, amt: (cat==='Income'? Math.abs(amt): amt)});
  }
  $('txBody').innerHTML=txs.map(t=>`<tr><td>${h(t.date)}</td><td>${h(t.desc)}</td><td><span class="chip">${h(t.cat)}</span></td><td style="text-align:right;font-weight:700">${t.amt>0? fmtUSD(t.amt): '<span style="color:#0a7a4b">'+fmtUSD(Math.abs(t.amt))+' credit</span>'}</td></tr>`).join('');

  // bars
  let bars=[32,48,27,62,41,58,35];
  $('bars').innerHTML=bars.map((v,i)=>`<div style="flex:1;background:${i===3?'var(--accent)':'#d9e1ff'};height:${v*1.4}px;border-radius:6px"></div>`).join('');

  // cards
  $('cards').innerHTML=`
    <div style="display:flex;gap:10px;align-items:center;background:linear-gradient(135deg,#0a2540,#635bff);color:#fff;border-radius:12px;padding:12px">
      <div style="flex:1"><div style="opacity:.8;font-size:11px">VISA Platinum</div><b>•••• 4821</b><div style="opacity:.85;font-size:12px">Exp 09/29 • Alex R.</div></div><div style="font-size:22px">◯ ◯</div></div>
    <div style="display:flex;gap:10px;align-items:center;background:linear-gradient(135deg,#1e293b,#0ea5e9);color:#fff;border-radius:12px;padding:12px">
      <div style="flex:1"><div style="opacity:.8;font-size:11px">Mastercard World</div><b>•••• 1104</b><div style="opacity:.85;font-size:12px">Exp 04/28 • Alex R.</div></div><div style="font-size:22px">◯ ◯</div></div>
  `;
}
load().catch(e=>{
  document.body.innerHTML='<div style="padding:18px"><h1>Real-bank view failed</h1><pre>'+h(e.message)+'</pre><p><a href=\"./\">Back to lab</a></p></div>';
});
</script></body></html>
"""

def render(public):
    p = Path(public) / "realbanks.html"
    p.write_text(HTML_REALBANKS)

def serve(public_dir, host="127.0.0.1", port=8082):
    from functools import partial
    import http.server
    from urllib.parse import unquote, urlsplit
    class PublicOnly(http.server.SimpleHTTPRequestHandler):
        def log_message(self,*a): pass
        def translate_path(self, path):
            rel=unquote(urlsplit(path).path).lstrip("/") or "realbanks.html"
            root=Path(self.directory).resolve()
            cand=root/rel
            if ".." in Path(rel).parts or cand.is_symlink() or not cand.resolve().is_relative_to(root):
                return str(root/"FORBIDDEN-NONEXISTENT")
            return str(cand)
        def list_directory(self,path):
            self.send_error(403,"Directory listing disabled"); return None
        def end_headers(self):
            self.send_header("X-Content-Type-Options","nosniff")
            self.send_header("Cache-Control","no-store")
            super().end_headers()
    if host not in ("127.0.0.1","0.0.0.0"):
        raise ValueError("only local/preview binds")
    srv=http.server.ThreadingHTTPServer((host,port), partial(PublicOnly, directory=str(public_dir)))
    print(f"Real-bank UI on {host}:{port} serving {public_dir} -> realbanks.html", flush=True)
    srv.serve_forever()
