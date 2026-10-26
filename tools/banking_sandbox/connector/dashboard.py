"""Connected dashboard: Product 1 (Sandbox) | Product 2 (CryptoScan) | Validation."""

from pathlib import Path
import json


TEMPLATE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ZELNX — Connected Lab: Sandbox + CryptoScan</title>
<style>
:root{color-scheme:dark;font:14px system-ui;background:#070c1c;color:#e7edf8}*{box-sizing:border-box}
body{margin:0;display:grid;grid-template-columns:240px 1fr;min-height:100vh}
aside{background:#0e1730;padding:28px 22px;border-right:1px solid #24304a;position:sticky;top:0;height:100vh;overflow:auto}
h1{font-size:18px;line-height:1.2;margin:0 0 8px}h2{font-size:15px;margin:0 0 10px}h3{font-size:13px;color:#9ab0d0;margin:16px 0 8px}
.muted{color:#9ba8c3;font-size:12px;line-height:1.6}.tag{display:inline-block;border:1px solid #567661;color:#a6f2ba;border-radius:5px;padding:4px 8px;font-size:11px;letter-spacing:.6px}
nav{display:grid;gap:14px;margin-top:28px}nav a{color:#dce6fa;text-decoration:none;font-size:13px}
main{padding:28px;max-width:1600px;width:100%}
.warning{background:#1c1a14;color:#f4cf84;padding:12px 16px;border:1px solid #66522e;border-radius:8px;line-height:1.6;font-size:12px;margin:12px 0}
.panel{background:#111b30;border:1px solid #293650;border-radius:10px;padding:18px;margin:14px 0}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.kpi{background:#141e34;border:1px solid #293650;border-radius:10px;padding:14px}
.kpi b{display:block;font-size:20px;color:#79e9d4;margin-top:6px}.kpi span{color:#adbbd2;font-size:11px}
.columns{display:grid;grid-template-columns:1fr 1fr;gap:14px}
table{width:100%;border-collapse:collapse}td,th{padding:8px 10px;text-align:left;border-bottom:1px solid #263550;font-size:12px;vertical-align:top}
th{color:#9ab0d0;font-weight:600}pre{font-size:11px;white-space:pre-wrap;overflow-wrap:anywhere;max-height:420px;overflow:auto;line-height:1.55;color:#b4c8e3;background:#0a1429;border:1px solid #253556;border-radius:8px;padding:12px}
a{color:#7dd7ff}footer{color:#92a0b8;line-height:1.7;font-size:11px;margin-top:18px}
.badge{padding:3px 7px;border-radius:999px;font-size:11px;border:1px solid #3a4a6a;color:#cbd6ea}
.ok{color:#9cf2c1}.warn{color:#f1cb72}.bad{color:#ff8d8d}
@media(max-width:980px){body{grid-template-columns:1fr}aside{display:none}.grid3{grid-template-columns:1fr}.columns{grid-template-columns:1fr}}
</style></head><body>
<aside>
<strong style="letter-spacing:.5px">ZELNX</strong><p class="muted">CONNECTED LAB<br>Product 1 · Product 2</p>
<span class="tag">SYNTHETIC · BOUNDARIED</span>
<nav>
<a href="#overview">◈ Overview</a>
<a href="#p1">▤ Product 1 — Sandbox</a>
<a href="#p2">⬢ Product 2 — CryptoScan</a>
<a href="#sixboms">◇ Six BOM Output</a>
<a href="#validation">≋ Validation · UNKNOWN≠SAFE</a>
<a href="#limits">⚑ Limits</a>
</nav>
<p class="muted" style="margin-top:60px">Two products. One local connector.<br>No shared DB. No shared secret.<br>Scanner never reads <code>control/</code>.</p>
<p class="muted">Connector: <code>products.connector.run</code><br>Sandbox API: <code>tools.banking_sandbox.cli</code><br>CryptoScan: <code>scanner + cbom/* + vendor_intel + hsm</code></p>
</aside>
<main>
<header style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
<div><p class="muted" style="margin:0">PRODUCT SPLIT — SAME REPO, SEPARATE ENTRY POINTS & DATA BOUNDARIES</p>
<h1>Banking Sandbox → CryptoScan: connected output</h1>
<p class="muted">Actual scanner findings, six BOM documents, operator validation. Unprobed stays unjudged.</p></div>
<span class="tag">CONNECTED OUTPUT · OFFLINE</span>
</header>

<div class="warning">Lab data only. <code>public/</code> fixtures are synthetic. Network/HBOM/VBOM rows in this demo are <b>FIXTURE_DERIVED_NOT_LIVE_PROBED</b> and are <b>never</b> claimed as live probed. Only the static source scan negotiates real boundaries (Landlock + seccomp with oracle/socket denial). See Limits.</div>

<section id="overview" class="panel">
<h2>Run overview</h2>
<div class="grid3" id="kpis"></div>
<div class="columns" style="margin-top:12px">
<div class="panel"><h3>Product 1 — what the lab advertised</h3><pre id="p1summary"></pre></div>
<div class="panel"><h3>Product 2 — what CryptoScan actually observed</h3><pre id="p2summary"></pre></div>
</div>
</section>

<section id="p1" class="panel">
<h2>Product 1 — Banking Sandbox (public fixtures)</h2>
<p class="muted">Generator truth is in <code>control/ground_truth</code> and is <b>never</b> staged to the scanner. The scanner sees only <code>public/</code>.</p>
<table><thead><tr><th>Metric</th><th>Value</th><th>Provenance</th></tr></thead><tbody id="p1table"></tbody></table>
<details style="margin-top:10px"><summary class="muted">Estate LAB.json</summary><pre id="labjson"></pre></details>
</section>

<section id="p2" class="panel">
<h2>Product 2 — CryptoScan (isolated scan + BOM build)</h2>
<p class="muted">Each collection ran in a Landlock + seccomp child: <code>ORACLE_SENTINEL</code> read → <span class="ok">PermissionError</span>, socket → <span class="ok">PermissionError</span>, wall/cpu/rss recorded. Collector source hash pinned.</p>
<div class="grid3"><div class="kpi"><span>Static files scanned</span><b id="files"></b><span id="files2"></span></div>
<div class="kpi"><span>LB config files scanned</span><b id="lbfiles"></b><span id="lbfiles2"></span></div>
<div class="kpi"><span>Collector errors</span><b id="errors"></b><span>failure = not NO_CRYPTO</span></div></div>
<table style="margin-top:12px"><thead><tr><th>Signal</th><th>Observed</th><th>Evidence</th></tr></thead><tbody id="p2table"></tbody></table>
<details><summary class="muted">Scan metrics (static + lb-config)</summary><pre id="scanmetrics"></pre></details>
</section>

<section id="sixboms" class="panel">
<h2>Six BOM output — built by real product generators</h2>
<p class="muted">Every document below came from a <b>real</b> generator: <code>CbomGenerator</code>, <code>materialize_technology_bom</code>, <code>generate_hbom</code>, <code>VbomGenerator</code>, <code>build_nbom</code>. Provenance on each component says <code>SCANNER_OBSERVED</code> vs <code>FIXTURE_DERIVED_NOT_LIVE_PROBED</code>.</p>
<table><thead><tr><th>BOM</th><th>Generator</th><th>Components / verdict</th><th>File</th></tr></thead><tbody id="bomtable"></tbody></table>
<div class="columns"><div><h3>TechBOM snapshot (unified)</h3><pre id="techbom"></pre></div><div><h3>CBOM sample</h3><pre id="cbom"></pre></div></div>
<div class="columns"><div><h3>HBOM fleet</h3><pre id="hbom"></pre></div><div><h3>VBOM summary</h3><pre id="vbom"></pre></div></div>
<div class="columns"><div><h3>NBOM (endpoints) — unobserved excluded</h3><pre id="nbom"></pre></div><div class="kpi" style="align-self:start"><h3 style="margin:0 0 6px">Artifacts on disk</h3><p class="muted">In <code>CRYPTO_SCAN_OUTPUT/</code>:</p><pre id="artifacts"></pre></div></div>
</section>

<section id="validation" class="panel">
<h2>Validation — operator step reading truth, never the scanner</h2>
<p class="muted"><b>UNKNOWN ≠ SAFE</b> · <b>INSTALLED ≠ USED</b> · missing file → no verdict · scanner truth comparison only on <code>ground_truth/*-static.jsonl</code> per-file families.</p>
<div class="grid3"><div class="kpi"><span>Precision</span><b id="prec"></b><span>tp / (tp+fp)</span></div>
<div class="kpi"><span>Recall</span><b id="rec"></b><span>tp / (tp+fn)</span></div>
<div class="kpi"><span>Failed / missing</span><b id="failr"></b><span>failure_rate; not NO_CRYPTO</span></div></div>
<table style="margin-top:12px"><thead><tr><th>Field</th><th>What is measured</th><th>Result</th></tr></thead><tbody id="valtable"></tbody></table>
<details><summary class="muted">Raw validation.json (operator-side)</summary><pre id="validationraw"></pre></details>
</section>

<section id="limits" class="panel">
<h2>Limits — not claimed as acceptance</h2>
<table><thead><tr><th>Claim</th><th>Status</th></tr></thead><tbody>
<tr><td>Full 15-mode product runtime coverage</td><td><span class="bad">Not claimed</span> — only static + lb-config exercised in this run</td></tr>
<tr><td>Network liveness / mTLS / HSM operation</td><td><span class="warn">Demo FIXTURE_DERIVED</span> — not a live probe; NBOM observed=false</td></tr>
<tr><td>LB hop ownership auto-detected</td><td><span class="warn">Topology-supplied</span> — controlled LB inventory, not ML detection</td></tr>
<tr><td>SBOM proves runtime usage</td><td><span class="bad">No</span> — lists declared packages</td></tr>
<tr><td>Key size / attribution / PQC readiness</td><td><span class="bad">UNKNOWN / VENDOR_DECLARED_NOT_VERIFIED</span> in this demo</td></tr>
<tr><td>Benchmark / SLA / prod capacity</td><td><span class="bad">Not measured</span> — wall time is operational sample</td></tr>
</tbody></table>
<footer>Products split: sandbox writes <code>ESTATE/</code> · scanner stages <code>scanner-inputs/</code> under Landlock/seccomp · connector writes <code>CRYPTOSCAN_OUTPUT/</code> · validation reads <code>control/ground_truth</code> only. Manifest hashes every output file.</footer>
</section>
</main>
<script>
'use strict';
async function j(path){let r=await fetch('../'+path,{cache:'no-store'});if(!r.ok) throw Error(path+': '+r.status);return r.json()}
function txt(path){return fetch('../'+path,{cache:'no-store'}).then(r=>{if(!r.ok) throw Error(path);return r.text()})}
function fmt(v){return v===null||v===undefined?'—':typeof v==='number'? (Number.isInteger(v)? v.toLocaleString(): v.toFixed(3)): String(v)}
(async()=>{
 let cat=await j('estate/catalog.json').catch(()=>null);
 let lab=await j('estate/LAB.json');
 let integ=await j('estate/integrity.json');
 let sc=await j('scan/static/metrics.json');
 let lb=await j('scan/lb-config/metrics.json').catch(()=>({files:0,errors:0,wall_seconds:0,note:'no lb-scan'}));
 let boms=await j('boms/summary.json');
 let val=await j('reports/validation.json');
 let mani=await j('manifest.json');
 let tech=await j('boms/techbom.json').catch(()=>null);
 let cbom=await j('boms/cbom.json').catch(()=>null);
 let hbom=await j('boms/hbom.json').catch(()=>null);
 let vbom=await j('boms/vbom.json').catch(()=>null);
 let nbom=await j('boms/nbom.json').catch(()=>null);

 // KPIs
 document.getElementById('kpis').innerHTML=[
   ['Banks (lab)', lab.options? lab.options.banks: integ.banks],
   ['Product 2 wall',''+(mani.wall_seconds||0).toFixed(1)+' s'],
   ['Boundary','oracle '+ (sc.boundary_receipt?.oracle_read_denied?'denied ✓':'?')+' · socket '+ (sc.boundary_receipt?.socket_creation_denied?'denied ✓':'?')],
 ].map(([k,v])=>'<div class=kpi><span>'+k+'</span><b>'+fmt(v)+'</b></div>').join('');

 document.getElementById('p1summary').textContent=JSON.stringify({integrity: integ, catalog_counts: cat?.counts||'see estate/catalog.json', options: lab.options},null,2);
 document.getElementById('p2summary').textContent=JSON.stringify({scan_static: {files: sc.files, errors: sc.errors??sc.failure_rate, wall_seconds: sc.wall_seconds, guard: sc.boundary_receipt}, scan_lb: lb, boms: boms},null,2);
 document.getElementById('labjson').textContent=JSON.stringify(lab,null,2);

 // tables
 const p1rows=[
   ['Banks', integ.banks, 'public/banks/*.json + catalog.json'],
   ['Base systems', integ.load_balancer_validation? 'see boms/techbom': (integ.systems||'—'), 'public/systems'],
   ['LB role instances', boms['lb-nbom']? JSON.stringify(boms['lb-nbom']): (integ.load_balancer_validation?.lb_nodes||'—'), 'public/load_balancers/*/inventory.json'],
   ['Public file hashes checked', integ.file_hashes_checked, 'manifest.json'],
   ['BOM documents schema-checked', integ.bom_documents_schema_checked??boms.techbom?.total_components, 'CycloneDX/SPDX validators'],
 ];
 document.getElementById('p1table').innerHTML=p1rows.map(r=>'<tr><td>'+r[0]+'</td><td>'+fmt(r[1])+'</td><td class=muted>'+r[2]+'</td></tr>').join('');

 document.getElementById('files').textContent=fmt(sc.files);
 document.getElementById('files2').textContent='wall '+fmt(sc.wall_seconds)+' s · cpu '+fmt(sc.boundary_receipt?.cpu_seconds||'—');
 document.getElementById('lbfiles').textContent=fmt(lb.files??lb.counts?.lb_config_files??0);
 document.getElementById('lbfiles2').textContent='errors '+fmt(lb.errors??0);
 document.getElementById('errors').textContent=fmt(sc.errors??0);

 document.getElementById('p2table').innerHTML=[
   ['Collector', 'scanner.registry.language_scanners.scan_file', sc.collector+'<br><span class=muted>'+ (sc.collector_source_sha256||'').slice(0,16)+'…</span>'],
   ['Guard', 'Landlock ABI '+fmt(sc.boundary_receipt?.landlock_abi)+' · seccomp '+fmt(sc.boundary_receipt?.seccomp), fmt(sc.boundary_receipt?.oracle_read_denied)+' / '+fmt(sc.boundary_receipt?.socket_creation_denied)],
   ['Findings sample', (boms.cbom?.components||0)+' CBOM components', '<a href=\"../scan/static/findings.jsonl\">findings.jsonl</a> · <a href=\"../scan/static/metrics.json\">metrics</a>'],
 ].map(r=>'<tr><td>'+r[0]+'</td><td>'+r[1]+'</td><td>'+r[2]+'</td></tr>').join('');
 document.getElementById('scanmetrics').textContent=JSON.stringify({static: sc, lb: lb},null,2);

 const bomrows=[
   ['CBOM', 'CbomGenerator.from_records', fmt(boms.cbom?.components)+' components', '<a href=\"../boms/cbom.json\">cbom.json</a> · <a href=\"../boms/cbom.xml\">xml</a>'],
   ['SBOM', 'TechBOM sbom layer (app_component)', fmt(boms.sbom?.components), '<a href=\"../boms/sbom.json\">sbom.json</a>'],
   ['TechBOM', 'materialize_technology_bom', fmt(boms.techbom?.total_components)+' total · fp '+ (boms.techbom?.fingerprint||'').slice(0,12)+'…', '<a href=\"../boms/techbom.json\">techbom.json</a>'],
   ['HBOM', 'generate_hbom', fmt(boms.hbom?.component_count)+' devices · hsm '+fmt(boms.hbom?.hsm_count), '<a href=\"../boms/hbom.json\">hbom.json</a> · <a href=\"../boms/hbom.cyclonedx.json\">cyclonedx</a>'],
   ['VBOM', 'VbomGenerator', fmt(boms.vbom?.vendors)+' vendors · '+fmt(boms.vbom?.crypto_entries)+' entries', '<a href=\"../boms/vbom.json\">vbom.json</a>'],
   ['NBOM', 'build_nbom', 'unobserved '+fmt(boms.nbom?.unobserved)+' · components '+fmt((nbom?.components||[]).length), '<a href=\"../boms/nbom.json\">nbom.json</a>'],
   ['LB NBOM', 'build_nbom (LB devices)', fmt(boms['lb-nbom']?.unobserved??0)+' unobserved', '<a href=\"../boms/lb-nbom.json\">lb-nbom.json</a>'],
 ];
 document.getElementById('bomtable').innerHTML=bomrows.map(r=>'<tr><td><b>'+r[0]+'</b></td><td class=muted>'+r[1]+'</td><td>'+r[2]+'</td><td>'+r[3]+'</td></tr>').join('');
 document.getElementById('techbom').textContent=tech? JSON.stringify({fingerprint: tech.fingerprint, snapshot_id: tech.snapshot_id, layers: tech.components_by_layer, deps: tech.dependency_count},null,2): '—';
 document.getElementById('cbom').textContent=cbom? JSON.stringify({bomFormat: cbom.bomFormat, specVersion: cbom.specVersion, components: (cbom.components||[]).slice(0,2)},null,2): '—';
 document.getElementById('hbom').textContent=hbom? JSON.stringify(hbom.metadata,null,2): '—';
 document.getElementById('vbom').textContent=vbom? JSON.stringify(vbom.summary,null,2): '—';
 document.getElementById('nbom').textContent=nbom? JSON.stringify({components: (nbom.components||[]).length, dependencies: (nbom.dependencies||[]).length, summary: boms.nbom},null,2): '—';
 document.getElementById('artifacts').textContent=(mani.files||[]).slice(0,12).map(f=>f.path+'  '+f.sha256.slice(0,8)).join('\\n')+'\\n… '+mani.files.length+' files · '+manifestNote();
 function manifestNote(){return 'connector '+ (mani.connector_version||'');}

 let acc=val.static_accuracy||{};
 document.getElementById('prec').textContent=fmt(acc.precision);
 document.getElementById('rec').textContent=fmt(acc.recall);
 document.getElementById('failr').textContent=fmt(acc.failed_or_missing_files)+' / '+fmt(acc.files)+' ('+fmt(acc.failure_rate)+')';
 document.getElementById('valtable').innerHTML=[
   ['Static per-file family', 'tp/tp+fp vs tp/tp+fn on ground_truth/*-static.jsonl', 'precision '+fmt(acc.precision)+' · recall '+fmt(acc.recall)+' · FPR_negative '+fmt(acc.false_positive_rate_negative_files)],
   ['Key size / attribution', 'Not measured in static family benchmark', '<span class=bad>UNKNOWN</span> — '+fmt(acc.key_size_correctness||'null') ],
   ['Network verdicts', 'Unobserved excluded', fmt(boms.nbom?.unobserved)+' unobserved, not judged SAFE'],
   ['LB hop correlation', 'Compare fixtures if present', fmt(val.lb_accuracy? JSON.stringify(val.lb_accuracy).slice(0,120): 'null')],
   ['Schema checks', 'CycloneDX/SPDX validators', JSON.stringify(val.schema_checks||{})],
 ].map(r=>'<tr><td>'+r[0]+'</td><td class=muted>'+r[1]+'</td><td>'+r[2]+'</td></tr>').join('');
 document.getElementById('validationraw').textContent=JSON.stringify(val,null,2);
})().catch(e=>{document.body.innerHTML='<pre style=\"color:#ff8d8d\">'+e.stack+'</pre>'});
</script>
</html>
"""


def render_dashboard(estate, output, integrity, scan_static, scan_lb, bom_summary, validation, inventory):
    out = Path(output)
    # copy catalog/LAB into dashboard-accessible estate snapshot for fetch
    est = out / "estate"
    est.mkdir(exist_ok=True)
    # light copies: catalog, LAB, integrity
    for name in ("catalog.json", "LAB.json"):
        src = estate / "public" / name if (estate / "public" / name).exists() else estate / name
        if src.exists():
            (est / name).write_bytes(src.read_bytes())
    (est / "integrity.json").write_text(json.dumps(integrity, indent=2))
    # dashboard index
    (out / "dashboard").mkdir(exist_ok=True)
    (out / "dashboard/index.html").write_text(TEMPLATE)


def serve_output(output: Path, host: str = "127.0.0.1", port: int = 8080):
    from functools import partial
    import http.server

    output = Path(output).resolve(strict=True)
    if (output / "dashboard/index.html").exists():
        directory = str(output)
    else:
        directory = str(output)

    # Serve the entire output directory (dashboard at /dashboard/)
    # Reuse the public-only handler but allow output files (no directory listing disabled)
    class OutputHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def list_directory(self, path):
            self.send_error(403, "Directory listing disabled")
            return None
        def end_headers(self):
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            super().end_headers()

    if host not in ("127.0.0.1", "0.0.0.0"):
        raise ValueError("only local/preview binds allowed")
    server = http.server.ThreadingHTTPServer((host, port), partial(OutputHandler, directory=directory))
    print(f"Connected output dashboard on {host}:{port} serving {directory}", flush=True)
    server.serve_forever()
