from __future__ import annotations
import html, json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

_SEV_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]
_SEV_COLOR = {"critical": "#991b1b", "high": "#dc2626", "medium": "#d97706",
              "low": "#16a34a", "info": "#64748b", "unknown": "#94a3b8"}
_CAT_LABEL = {"pkg-vuln": "package/CVE", "secret": "secret", "image-config": "image config",
              "web-vuln": "web", "network-vuln": "network", "malware": "malware",
              "sbom-component": "component (SBOM)", "other": "other"}


def _esc(x) -> str:
    return html.escape(str(x if x is not None else ""))


def _sev_chip(s: str) -> str:
    return f'<span class="chip" style="background:{_SEV_COLOR.get(s, "#94a3b8")}">{_esc(s)}</span>'


def _n(x) -> str:
    try:
        return f"{int(x):,}".replace(",", " ")
    except (TypeError, ValueError):
        return _esc(x)


_CSS = """
*{box-sizing:border-box}
:root{--bg:#f6f7f9;--fg:#1e293b;--mut:#64748b;--line:#e2e8f0;--card:#fff;--accent:#0f766e;--accent-d:#0b1220}
html{scroll-behavior:smooth;scroll-padding-top:60px}
body{font:14.5px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;margin:0;color:var(--fg);background:var(--bg)}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
header.top{background:var(--accent-d);color:#e2e8f0;padding:26px 22px 22px}
header.top h1{margin:0;font-size:21px;font-weight:650;letter-spacing:-.01em}
header.top .sub{color:#94a3b8;font-size:13px;margin-top:6px;max-width:900px}
header.top code{color:#5eead4}
nav.sticky{position:sticky;top:0;z-index:20;background:rgba(255,255,255,.93);backdrop-filter:blur(6px);border-bottom:1px solid var(--line);padding:8px 22px;display:flex;gap:18px;flex-wrap:wrap;font-size:13px;font-weight:550}
nav.sticky a{color:var(--mut)}nav.sticky a:hover{color:var(--fg)}
main{max-width:1180px;margin:0 auto;padding:18px 22px 60px}
section{margin:34px 0 0}
h2{font-size:16.5px;font-weight:650;margin:0 0 4px;letter-spacing:-.01em}
h2 .sub{font-weight:400;font-size:13px;color:var(--mut);margin-left:2px}
p.note{color:var(--mut);font-size:13px;margin:6px 0 14px;max-width:940px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:13px 15px}
.card .v{font-size:23px;font-weight:680;letter-spacing:-.02em}
.card .l{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.05em;margin-top:3px}
.card .s{font-size:11.5px;color:var(--mut);margin-top:4px}
.legend{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:11px 14px;font-size:13px;margin:0 0 10px}
.chip{display:inline-block;padding:1px 8px;border-radius:11px;color:#fff;font-size:11px;font-weight:600;vertical-align:1px}
table{border-collapse:collapse;width:100%;background:var(--card);font-size:13px;border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:7px 11px;border-bottom:1px solid #f1f5f9;vertical-align:top}
th{background:#fbfcfd;font-weight:600;color:#334155;cursor:pointer;user-select:none;white-space:nowrap}
th.no-sort{cursor:default}
tbody tr:hover{background:#fafbfc}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.b{font-weight:600}.muted{color:var(--mut)}.warn{color:#b45309;font-size:11px;font-weight:600}
.sevbar{display:inline-flex;height:11px;border-radius:3px;overflow:hidden;vertical-align:middle;background:#eef1f4}
.sevbar span{display:block;height:100%}
.hbar{display:inline-block;width:90px;height:9px;border-radius:5px;background:#eef1f4;vertical-align:middle;overflow:hidden}
.hbar span{display:block;height:100%;background:var(--accent)}
.heat td{text-align:right;font-variant-numeric:tabular-nums}
.toolbar{display:flex;gap:10px;align-items:center;margin:10px 0 0}
.toolbar input{flex:1;max-width:340px;padding:6px 10px;border:1px solid var(--line);border-radius:8px;font:inherit}
.scroll{max-height:560px;overflow:auto;border:1px solid var(--line);border-radius:10px}
.scroll table{border:0;border-radius:0}.scroll th{position:sticky;top:0}
footer{margin-top:46px;padding-top:18px;border-top:1px solid var(--line);color:var(--mut);font-size:12.5px}
@media(max-width:640px){nav.sticky{gap:12px}}
"""

_JS = r"""
const D = JSON.parse(document.getElementById('data').textContent);
const SEV = ['critical','high','medium','low','info','unknown'];
const SEVC = {critical:'#991b1b',high:'#dc2626',medium:'#d97706',low:'#16a34a',info:'#64748b',unknown:'#94a3b8'};
const esc = s => String(s==null?'':s).replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const nf = n => (typeof n==='number' ? n.toLocaleString('en-US') : esc(n));
const chip = s => `<span class="chip" style="background:${SEVC[s]||'#94a3b8'}">${esc(s)}</span>`;
function sevbar(o,w){ w=w||110; const t = SEV.reduce((a,s)=>a+(o[s]||0),0)||1;
  const seg = SEV.filter(s=>o[s]).map(s=>`<span title="${s}: ${o[s]}" style="background:${SEVC[s]};width:${(o[s]/t*100).toFixed(2)}%"></span>`).join('') || '<span style="background:#e2e8f0;width:100%"></span>';
  return `<span class="sevbar" style="width:${w}px">${seg}</span>`; }

// severity x category heatmap
(function(){ const tb = document.querySelector('#t-sxc tbody'); const colT = {}; let gT=0; let mx=1;
  SEV.forEach(sv=>{ const row=D.sxc[sv]||{}; D.cats.forEach(c=>{ if((row[c]||0)>mx) mx=row[c]; }); });
  SEV.forEach(sv=>{ const row=D.sxc[sv]||{}; let tot=0;
    const tds = D.cats.map(c=>{ const v=row[c]||0; tot+=v; colT[c]=(colT[c]||0)+v; const a=v?Math.sqrt(v/mx):0;
      return `<td style="background:rgba(153,27,27,${(a*0.55).toFixed(3)})">${v?nf(v):'·'}</td>`; }).join('');
    gT+=tot; tb.insertAdjacentHTML('beforeend', `<tr><td>${chip(sv)}</td>${tds}<td class="b">${nf(tot)}</td></tr>`); });
  tb.insertAdjacentHTML('beforeend', `<tr style="font-weight:600;background:#fbfcfd"><td>total</td>${D.cats.map(c=>`<td>${nf(colT[c]||0)}</td>`).join('')}<td>${nf(gT)}</td></tr>`);
})();

// most exposed
(function(){ const set=new Set(D.most_exposed);
  const rows=D.targets.filter(r=>set.has(r.name)).sort((a,b)=>(b.crit*4+b.high)-(a.crit*4+a.high));
  document.querySelector('#t-exp tbody').innerHTML = rows.map(r=>`<tr><td class="mono b">${esc(r.name)}</td><td class="mono">${esc(r.image)}</td><td class="mono">${esc(r.ip)}</td><td class="muted">${esc(r.category)}</td><td class="num">${nf(r.n)}</td><td class="num">${nf(r.crit)}</td><td class="num">${nf(r.high)}</td><td>${sevbar(r,140)}</td></tr>`).join('');
})();

// generic sortable + filterable table
function mkTable(sel, rows, cols, filterIn, countEl){
  const tb = document.querySelector(sel+' tbody'); const ths = document.querySelectorAll(sel+' thead th');
  let sortI=-1, asc=false, q='';
  function txtOf(r){ return cols.map(c=>String(c.t?c.t(r):(r[c.k]??''))).join(' ').toLowerCase(); }
  function view(){ let rs=rows;
    if(q){ const qq=q.toLowerCase(); rs=rs.filter(r=>txtOf(r).includes(qq)); }
    if(sortI>=0){ const c=cols[sortI]; rs=rs.slice().sort((a,b)=>{ let x=c.s?c.s(a):a[c.k], y=c.s?c.s(b):b[c.k];
      if(x==null) x=c.num?-Infinity:''; if(y==null) y=c.num?-Infinity:'';
      return c.num ? (asc?x-y:y-x) : (asc?String(x).localeCompare(String(y)):String(y).localeCompare(String(x))); }); }
    tb.innerHTML = rs.map(r=>'<tr>'+cols.map(c=>`<td class="${c.cls||''}">${c.r(r)}</td>`).join('')+'</tr>').join('');
    if(countEl) countEl.textContent = rs.length===rows.length ? '' : (rs.length+' / '+rows.length); }
  ths.forEach((th,i)=>{ if(th.classList.contains('no-sort'))return; th.addEventListener('click',()=>{ if(sortI===i)asc=!asc; else{sortI=i;asc=false;} view(); }); });
  if(filterIn) filterIn.addEventListener('input', e=>{ q=e.target.value; view(); });
  view();
}
mkTable('#t-cont', D.targets, [
  {k:'name',cls:'mono b',r:r=>esc(r.name)}, {k:'image',cls:'mono',r:r=>esc(r.image)}, {k:'ip',cls:'mono',r:r=>esc(r.ip)},
  {k:'category',cls:'muted',r:r=>esc(r.category)}, {k:'n',num:true,cls:'num',r:r=>nf(r.n)},
  {k:'crit',num:true,cls:'num',r:r=>nf(r.crit)}, {k:'high',num:true,cls:'num',r:r=>nf(r.high)},
  {k:'med',num:true,cls:'num',r:r=>nf(r.med)}, {k:'low',num:true,cls:'num',r:r=>nf(r.low)}, {k:'info',num:true,cls:'num',r:r=>nf(r.info)},
  {k:'_b',cls:'',num:true,s:r=>r.crit*4+r.high,r:r=>sevbar(r,120),t:r=>''}, {k:'note',cls:'muted',r:r=>esc(r.note)},
], document.getElementById('q-cont'), document.getElementById('q-cont-n'));
mkTable('#t-find', D.findings, [
  {k:'sev',num:true,cls:'',s:r=>SEV.indexOf(r.sev)*1000-(r.cvss||0),r:r=>chip(r.sev),t:r=>r.sev},
  {k:'cvss',num:true,cls:'num',r:r=>r.cvss!=null?r.cvss:'·'},
  {k:'id',cls:'mono b',r:r=>r.ref?`<a href="${esc(r.ref)}" target="_blank" rel="noopener">${esc(r.id)}</a>`:esc(r.id)},
  {k:'title',cls:'',r:r=>esc(r.title)}, {k:'cat',cls:'muted',r:r=>esc(r.cat)},
  {k:'pkg',cls:'mono',r:r=>esc(r.pkg)},
  {k:'_vf',cls:'mono muted',s:r=>r.ver,r:r=>esc(r.ver)+(r.fix?' → '+esc(r.fix):''),t:r=>r.ver+' '+r.fix},
  {k:'target',cls:'mono',r:r=>esc(r.target)}, {k:'ip',cls:'mono',r:r=>esc(r.ip)},
  {k:'by',cls:'mono muted',s:r=>(r.by||[]).join(','),r:r=>esc((r.by||[]).join(', ')),t:r=>(r.by||[]).join(' ')},
], document.getElementById('q-find'), document.getElementById('q-find-n'));

// make the server-rendered scanner-coverage table sortable
(function(){ const t=document.getElementById('t-scan'); if(!t)return; const tb=t.tBodies[0]; const ths=t.tHead.rows[0].cells;
  Array.from(ths).forEach((th,i)=>{ if(th.classList.contains('no-sort'))return; let asc=false;
    th.addEventListener('click',()=>{ asc=!asc; const rs=Array.from(tb.rows).sort((a,b)=>{
      const x=parseFloat(a.cells[i].textContent.replace(/[^\d.\-]/g,''))||0, y=parseFloat(b.cells[i].textContent.replace(/[^\d.\-]/g,''))||0; return asc?x-y:y-x; }); rs.forEach(r=>tb.appendChild(r)); }); });
})();
"""


def render(corpus: dict, out_path: Path) -> None:
    s = corpus.get("summary", {}) or {}
    targets = corpus.get("targets", []) or []
    findings = corpus.get("findings", []) or []
    by_sev = s.get("findings_by_severity", {}) or {}
    by_cat = s.get("findings_by_category", {}) or {}
    sc_stats = s.get("scanner_stats", {}) or {}
    thru = s.get("throughput", {}) or {}
    agr = s.get("pkg_vuln_agreement", {}) or {}
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    n_targets = s.get("targets_scanned") or s.get("targets") or len(targets)
    n_findings = s.get("findings_merged") or len(findings)
    n_scanners = len([k for k, v in sc_stats.items() if v.get("ok", 0) and v.get("runs", 0)]) or s.get("scanners", 0)
    distinct_cves = len({c.upper() for f in findings for c in (f.get("cves") or []) if c})

    per_t: dict[str, Counter] = defaultdict(Counter)
    for f in findings:
        per_t[f.get("target_name", "")][f.get("severity", "unknown")] += 1
    sxc: dict[str, Counter] = defaultdict(Counter)
    for f in findings:
        sxc[f.get("severity", "unknown")][f.get("category", "other")] += 1
    cats_seen = sorted(by_cat.keys(), key=lambda c: -by_cat[c]) or sorted({f.get("category", "other") for f in findings})

    t_rows = []
    for t in targets:
        name = t.get("name", "")
        sv = per_t.get(name, Counter())
        t_rows.append({
            "name": name, "image": t.get("image", ""),
            "ip": t.get("ip") or t.get("container_ip") or "",
            "category": (t.get("meta") or {}).get("Category", ""),
            "n": int(sum(sv.values())),
            "crit": sv.get("critical", 0), "high": sv.get("high", 0), "med": sv.get("medium", 0),
            "low": sv.get("low", 0), "info": sv.get("info", 0), "unk": sv.get("unknown", 0),
            "note": t.get("skipped_reason", "") or "",
        })

    sev_rank = {s_: i for i, s_ in enumerate(_SEV_ORDER)}
    top = sorted(findings, key=lambda f: (sev_rank.get(f.get("severity", "unknown"), 9),
                                          -(f.get("cvss") or 0.0), f.get("target_name", "")))[:400]
    f_rows = [{
        "sev": f.get("severity", "unknown"), "id": f.get("id", "") or (f.get("title", "")[:40]),
        "cvss": f.get("cvss"), "title": (f.get("title", "") or "")[:160], "cat": f.get("category", "other"),
        "pkg": f.get("package", "") or f.get("endpoint", "") or (f.get("location", "")[:60]),
        "ver": f.get("version", ""), "fix": f.get("fixed_version", ""),
        "target": f.get("target_name", ""), "ip": f.get("target_ip") or "",
        "by": f.get("found_by") or ([f["scanner"]] if f.get("scanner") else []),
        "ref": (f.get("references") or [""])[0],
    } for f in top]

    most_exposed = [r["name"] for r in sorted(t_rows, key=lambda r: -(r["crit"] * 4 + r["high"]))[:25]]
    data = {"summary": s, "targets": t_rows, "findings": f_rows,
            "sxc": {sv: dict(sxc.get(sv, {})) for sv in _SEV_ORDER}, "cats": cats_seen, "most_exposed": most_exposed}

    def card(value, label, sub=""):
        return (f'<div class="card"><div class="v">{value}</div><div class="l">{_esc(label)}</div>'
                + (f'<div class="s">{_esc(sub)}</div>' if sub else "") + "</div>")

    cards = "".join([
        card(_n(n_targets), "containers scanned"),
        card(_n(n_findings), "findings (consolidated)"),
        card(_n(by_sev.get("critical", 0)), "critical", f'+{_n(by_sev.get("high", 0))} high'),
        card(_n(distinct_cves) if distinct_cves else "—", "distinct CVEs"),
        card(_n(n_scanners), "scanners (with output)"),
        card(f'{thru.get("targets_per_hour", "?")}', "containers / hour",
             f'≈ {thru.get("avg_seconds_per_target", "?")} s per container'),
    ])
    sev_legend = " ".join(f'{_sev_chip(k)} {_n(by_sev.get(k, 0))}' for k in _SEV_ORDER if by_sev.get(k))
    cat_legend = " &nbsp; ".join(f'<b>{_n(v)}</b> {_esc(_CAT_LABEL.get(k, k))}'
                                 for k, v in sorted(by_cat.items(), key=lambda kv: -kv[1]))

    max_merged = max((v.get("merged_findings", 0) for v in sc_stats.values()), default=1) or 1
    sc_rows = []
    for name, b in sorted(sc_stats.items(), key=lambda kv: -kv[1].get("merged_findings", 0)):
        runs, ok = b.get("runs", 0), b.get("ok", 0)
        okpct = f"{ok / runs * 100:.0f}%" if runs else "—"
        merged = b.get("merged_findings", 0)
        flag = ""
        if runs and ok == 0:
            flag = ' <span class="warn">falhou em todas</span>'
        elif runs and ok < runs:
            flag = f' <span class="warn">{runs - ok} erro(s)</span>'
        if name == "clamav":
            flag += ' <span class="muted">(parcial — removido: lento)</span>'
        sc_rows.append(
            f'<tr><td class="mono b">{_esc(name)}{flag}</td><td class="num">{_n(runs)}</td>'
            f'<td class="num">{okpct}</td><td class="num">{b.get("avg_wall_s", "?")} s</td>'
            f'<td class="num">{_n(round(b.get("peak_mem_mb", 0)))} MB</td><td class="num">{_n(b.get("raw_findings", 0))}</td>'
            f'<td class="num">{_n(merged)}</td><td><span class="hbar"><span style="width:{merged / max_merged * 100:.1f}%"></span></span> '
            f'{merged / (n_findings or 1) * 100:.1f}%</td></tr>')

    n_pv = by_cat.get("pkg-vuln", 0) or 1
    agr_rows = "".join(
        f'<tr><td>encontrado por <b>{_esc(k)}{"+" if k == "4" else ""}</b> scanner(s) de CVE</td>'
        f'<td class="num">{_n(v)}</td><td class="num">{v / n_pv * 100:.1f}%</td></tr>'
        for k, v in sorted(agr.items(), key=lambda kv: int(kv[0])))
    thru_rows = "".join(
        f'<tr><td>{_esc(k)}</td><td class="num mono">{_esc(v)}</td></tr>' for k, v in [
            ("wall-clock (s)", thru.get("wall_clock_seconds")),
            ("containers / minute", thru.get("targets_per_minute")),
            ("containers / hour", thru.get("targets_per_hour")),
            ("mean s / container", thru.get("avg_seconds_per_target")),
            ("median s / container", thru.get("median_seconds_per_target")),
            ("scanner CPU-seconds (total)", thru.get("scanner_cpu_seconds_total")),
            ("effective parallelism (concurrent scanner-containers)", thru.get("parallel_efficiency")),
        ] if v is not None)
    sxc_head = "".join(f'<th class="no-sort num">{_esc(_CAT_LABEL.get(c, c))}</th>' for c in cats_seen)

    head = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AnonymousSystem · multi-scanner scan of vulnerable containers</title>
<style>{_CSS}</style></head><body>
<header class="top">
  <h1>AnonymousSystem — multi-scanner scan of vulnerable containers</h1>
  <div class="sub"><b>{_n(n_targets)}</b> vulnerable container images (corpus <code>lab-corpus</code>) scanned by a battery of <b>{_n(n_scanners)}</b> static security scanners, on two machines, via the distributed pipeline <a href="https://anonymous.4open.science/r/AnonymousSystem-2131/">AnonymousSystem/scanners</a>. <b>{_n(n_findings)}</b> consolidated findings; each traces back to the image (and the container IP) that originated it. Generated on {gen}.</div>
</header>
<nav class="sticky">
  <a href="#summary">Summary</a><a href="#performance">Performance</a><a href="#scanners">Coverage per scanner</a>
  <a href="#agreement">Agreement</a><a href="#severity">Severity × category</a>
  <a href="#exposed">Most exposed</a><a href="#containers">All containers</a><a href="#findings">Findings</a>
</nav>
<main>
<section id="summary">
  <h2>Summary <span class="sub">what was measured</span></h2>
  <p class="note">Static battery (scans the image's <code>docker save</code> tar and the flattened rootfs — no need to run the container): <b>syft</b> (SBOM), <b>trivy</b> · <b>grype</b> · <b>osv-scanner</b> · <b>clair</b> (package CVEs, four engines), <b>dockle</b> (best practices/image config), <b>trufflehog</b> (secrets). The {_n(n_targets)} containers already had OpenVAS results collected (dynamic network scanner — reference). Slow (clamav) or broken (semgrep — config error) filesystem scanners appear in the tables, flagged, but produced no findings.</p>
  <div class="cards">{cards}</div>
  <div class="legend"><b>Severity:</b> &nbsp; {sev_legend}</div>
  <div class="legend"><b>Category:</b> &nbsp; {cat_legend}</div>
</section>
<section id="performance">
  <h2>Performance <span class="sub">scan throughput</span></h2>
  <p class="note">End-to-end throughput of the {_n(n_targets)} containers (includes worker-restart intervals — in steady state it was faster). <b>Effective parallelism</b> = average number of scanner containers running at the same time.</p>
  <table style="max-width:560px"><thead><tr><th class="no-sort">metric</th><th class="no-sort num">value</th></tr></thead><tbody>{thru_rows}</tbody></table>
</section>
<section id="scanners">
  <h2>Coverage per scanner</h2>
  <p class="note"><b>runs</b> = invocations · <b>ok</b> = % that finished with useful output · <b>mean time</b> = wall per invocation · <b>raw → consolidated</b> = after intra-scanner dedup · <b>share</b> = % of the consolidated total. Click to sort.</p>
  <table id="t-scan"><thead><tr><th class="no-sort">scanner</th><th class="num">runs</th><th class="num">ok</th><th class="num">mean time</th><th class="num">peak mem.</th><th class="num">raw</th><th class="num">consolidated</th><th class="no-sort">share</th></tr></thead><tbody>{''.join(sc_rows)}</tbody></table>
</section>
<section id="agreement">
  <h2>Agreement among the CVE scanners <span class="sub">trivy · grype · osv · clair</span></h2>
  <p class="note">These scanners measure the <i>same</i> thing (package CVEs) — it only counts as "agreement" when the same CVE is reported for the same package at the same path. The exact agreement is low partly because the scanners normalize package names differently (<code>org.apache.activemq:activemq-client</code> vs <code>activemq-client</code>) — not because any one is wrong. Trufflehog (secrets), syft (components) and dockle (config) measure other things and do not enter here.</p>
  <table style="max-width:560px"><thead><tr><th class="no-sort">agreement</th><th class="no-sort num">package CVEs</th><th class="no-sort num">% of CVEs</th></tr></thead><tbody>{agr_rows or '<tr><td class="muted" colspan="3">no package vulns</td></tr>'}</tbody></table>
</section>
<section id="severity">
  <h2>Severity × category</h2>
  <p class="note">Consolidated findings at each severity × category intersection (intensity ∝ √count).</p>
  <table class="heat" id="t-sxc"><thead><tr><th class="no-sort">severity</th>{sxc_head}<th class="no-sort num">total</th></tr></thead><tbody></tbody></table>
</section>
<section id="exposed">
  <h2>Most exposed containers <span class="sub">top 25 by (critical×4 + high)</span></h2>
  <p class="note">Where the high-severity findings concentrate. <code>IP</code> is the container's address in the lab — the vuln↔container correlation key.</p>
  <table id="t-exp"><thead><tr><th>container</th><th>image</th><th>IP</th><th>category</th><th class="num">findings</th><th class="num">crit.</th><th class="num">high</th><th class="no-sort">severity</th></tr></thead><tbody></tbody></table>
</section>
<section id="containers">
  <h2>All {_n(len(t_rows))} containers</h2>
  <p class="note">Click a header to sort; filter by name/image/IP/category.</p>
  <div class="toolbar"><input id="q-cont" placeholder="filter containers…"><span class="muted" id="q-cont-n"></span></div>
  <div class="scroll"><table id="t-cont"><thead><tr><th>container</th><th>image</th><th>IP</th><th>category</th><th class="num">findings</th><th class="num">crit.</th><th class="num">high</th><th class="num">medium</th><th class="num">low</th><th class="num">info</th><th class="no-sort">severity</th><th>notes</th></tr></thead><tbody></tbody></table></div>
</section>
<section id="findings">
  <h2>Highest-severity findings <span class="sub">top {_n(len(f_rows))}</span></h2>
  <p class="note">Sorted by severity and CVSS. Filter by CVE, package, container, IP, scanner. (The complete set — {_n(n_findings)} findings — is in <code>findings.jsonl</code>; each scanner's native outputs, in <b>every format they emit</b>, are in <code>out/&lt;container&gt;/&lt;scanner&gt;/</code>.)</p>
  <div class="toolbar"><input id="q-find" placeholder="filter findings…"><span class="muted" id="q-find-n"></span></div>
  <div class="scroll"><table id="t-find"><thead><tr><th>sev</th><th class="num">CVSS</th><th>id</th><th>title</th><th>category</th><th>package / location</th><th>version → fix</th><th>container</th><th>IP</th><th>seen by</th></tr></thead><tbody></tbody></table></div>
</section>
<footer>
  <p><b>Methodology.</b> Pipeline <a href="https://anonymous.4open.science/r/AnonymousSystem-2131/">AnonymousSystem/scanners</a> — distributed work queue, one Docker container per scanner (hardened: <code>cap-drop ALL</code>, read-only rootfs, memory/PID limits, isolated network), finding normalization and dedup with <code>found_by</code>, import of OpenVAS results by IP. Severity <code>unknown</code> = no rating/CVSS assigned by the scanner. "consolidated" = after intra-scanner dedup (same CVE/package/path).</p>
  <p>Earlier methodological comparison (35 tools × 3 canonical targets): <a href="scanner-bench-35tools.html">scanner-bench-35tools.html</a> · Generated on {gen}.</p>
</footer>
</main>"""

    doc = (head
           + '\n<script id="data" type="application/json">'
           + json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
           + "</script>\n<script>" + _JS + "</script>\n</body></html>\n")
    out_path.write_text(doc)
