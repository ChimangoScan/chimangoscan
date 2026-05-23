#!/usr/bin/env python3
"""Inject DETAIL data + a single data-driven renderer into the HTML.

Replaces the previous N hand-written render functions with one universal
renderScanner(name) that consumes a VIZ_SPECS object built from declarative
per-scanner specs. Adding a new renderer is just adding an entry to
VIZ_SPECS in this file — no new JS function.
"""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTML = ROOT / "reports" / "scanner-comparison.html"
DETAIL_JSON = ROOT / "reports" / "scans-output" / "_detail.json"

sys.path.insert(0, str(ROOT / "scripts"))
from scanner_specs import SCANNERS  # noqa: E402


# ─── Viz specs (declarative) ────────────────────────────────────────────────
# Each scanner's viz is described as data, not code. The JS engine reads this
# object and produces cards / donut / stacked / hbar / table accordingly.
#
# Card spec   : { label, expr, sub, accent }
# Chart spec  : { kind: 'donut'|'hbar'|'stacked'|'cvss-bins',
#                 title, field, color: 'severity'|'eco'|<hex>, limit, order? }
# Table column: { title, field, kind: 'badge-sev'|'cve'|'pkg'|'mono'|'wrap'|'num' }

def _spec(scanner: str, **kwargs) -> dict:
    return {"scanner": scanner, **kwargs}


VIZ_SPECS = {
    "openvas": _spec("openvas",
        sev_field="threat",
        sev_order=["Critical", "Alarm", "High", "Medium", "Low", "Log"],
        sev_palette={"Critical":"#7f1d1d","Alarm":"#a91e1e","High":"#b91c1c",
                     "Medium":"#b45309","Low":"#0d6e3e","Log":"#6b7280"},
        cards=[
            {"label":"findings (NVTs)", "expr":"count", "sub":"3 targets combined"},
            {"label":"max CVSS", "expr":"max:severity", "accent":"#b91c1c",
             "sub_expr":"avg:severity", "sub_prefix":"mean "},
            {"label":"with CVE", "expr":"countNonEmpty:cves",
             "sub_expr":"pctNonEmpty:cves", "sub_suffix":" of findings"},
            {"label":"families / ports", "expr":"unique_pair:family,port",
             "sub":"surface coverage"},
        ],
        charts=[
            {"kind":"donut+hbar", "title":"severity (Threat)", "color":"severity",
             "field":"threat"},
            {"kind":"stacked", "title":"severity × target", "color":"severity",
             "field":"threat", "span":2},
            {"kind":"hbar", "title":"top NVT families", "field":"family", "limit":8},
            {"kind":"hbar", "title":"target ports", "field":"port", "limit":8},
            {"kind":"hbar", "title":"top NVTs (most fired)", "field":"name", "limit":8},
        ],
        table=[
            {"title":"NVT", "field":"name", "kind":"wrap"},
            {"title":"Threat", "field":"threat", "kind":"badge-sev"},
            {"title":"CVSS", "field":"severity", "kind":"num1"},
            {"title":"Port", "field":"port", "kind":"mono"},
            {"title":"Family", "field":"family", "kind":"pkg"},
            {"title":"CVE", "field":"cves", "kind":"cve"},
            {"title":"QoD", "field":"qod", "kind":"qod"},
        ],
        sort_by="threat", secondary_sort="severity:desc",
    ),
    "osv": _spec("osv",
        sev_field=None,
        cards=[
            {"label":"OSV vulns", "expr":"count", "sub":"3 targets summed"},
            {"label":"unique CVEs", "expr":"unique:cve",
             "sub_expr":"pct_unique:cve", "sub_suffix":" without dup"},
            {"label":"vulnerable packages", "expr":"unique_pair:ecosystem,pkg"},
            {"label":"CVSS ≥ 7 (high+)", "expr":"countGte:cvss:7", "accent":"#b91c1c",
             "sub_expr":"pctGte:cvss:7"},
        ],
        charts=[
            {"kind":"donut+hbar", "title":"ecosystems", "color":"eco",
             "field":"ecosystem", "limit":8},
            {"kind":"cvss-bins", "title":"CVSS distribution", "field":"cvss"},
            {"kind":"stacked", "title":"ecosystem × target", "color":"eco",
             "field":"ecosystem"},
            {"kind":"hbar", "title":"top 12 vulnerable packages",
             "field":"pkg_eco", "limit":12, "span":3},
        ],
        table=[
            {"title":"CVE / ID", "field":"cve", "kind":"cve"},
            {"title":"CVSS", "field":"cvss", "kind":"num1"},
            {"title":"Ecosystem", "field":"ecosystem", "kind":"tag-eco"},
            {"title":"Package", "field":"pkg", "kind":"pkg"},
            {"title":"Version", "field":"version", "kind":"mono"},
            {"title":"Target", "field":"target", "kind":"plain"},
            {"title":"Summary", "field":"summary", "kind":"wrap"},
        ],
        sort_by="cvss:desc", row_limit=1500,
    ),
    "detect-secrets": _spec("detect-secrets",
        sev_field=None,
        cards=[
            {"label":"leaks detected", "expr":"count", "sub":"baseline-style, no verification"},
            {"label":"verified", "expr":"countTrue:is_verified", "accent":"#b91c1c"},
            {"label":"unique types", "expr":"unique:type"},
            {"label":"unique files", "expr":"unique:file"},
        ],
        charts=[
            {"kind":"donut+hbar", "title":"type (plugin)", "color":"hash",
             "field":"type", "limit":8},
            {"kind":"hbar", "title":"per target", "field":"target", "color":"target"},
            {"kind":"hbar", "title":"top 12 files", "field":"file", "limit":12, "span":1},
        ],
        table=[
            {"title":"Type", "field":"type", "kind":"badge"},
            {"title":"Target", "field":"target", "kind":"plain"},
            {"title":"File", "field":"file", "kind":"pkg"},
            {"title":"Line", "field":"line_number", "kind":"num"},
            {"title":"Verified", "field":"is_verified", "kind":"bool"},
        ],
        sort_by="file", row_limit=1000,
    ),
    "checkov": _spec("checkov",
        sev_field="severity",
        sev_order=["CRITICAL","HIGH","MEDIUM","LOW","INFO","UNKNOWN"],
        sev_palette={"CRITICAL":"#7f1d1d","HIGH":"#b91c1c","MEDIUM":"#b45309",
                     "LOW":"#0d6e3e","INFO":"#6b7280","UNKNOWN":"#94a3b8"},
        cards=[
            {"label":"failing checks", "expr":"count"},
            {"label":"frameworks", "expr":"unique:framework"},
            {"label":"unique checks", "expr":"unique:check_id"},
            {"label":"affected files", "expr":"unique:file_path"},
        ],
        charts=[
            {"kind":"donut+hbar", "title":"severity", "color":"severity",
             "field":"severity"},
            {"kind":"hbar", "title":"per framework", "field":"framework"},
            {"kind":"stacked", "title":"severity × target", "color":"severity",
             "field":"severity"},
            {"kind":"hbar", "title":"top 12 checks (most failures)", "field":"check_id",
             "limit":12, "span":3},
        ],
        table=[
            {"title":"Check ID", "field":"check_id", "kind":"cve"},
            {"title":"Sev", "field":"severity", "kind":"badge-sev"},
            {"title":"Framework", "field":"framework", "kind":"tag"},
            {"title":"Resource", "field":"resource", "kind":"pkg"},
            {"title":"File", "field":"file_path", "kind":"pkg"},
            {"title":"Name", "field":"check_name", "kind":"wrap"},
            {"title":"Target", "field":"target", "kind":"plain"},
        ],
        sort_by="severity",
    ),
    "arachni": _spec("arachni",
        sev_field="severity",
        sev_order=["high","medium","low","informational"],
        sev_palette={"high":"#b91c1c","medium":"#b45309","low":"#0d6e3e",
                     "informational":"#1d4ed8"},
        cards=[
            {"label":"DAST issues", "expr":"count"},
            {"label":"unique CWEs", "expr":"uniqueNonEmpty:cwe"},
            {"label":"unique URLs", "expr":"unique:url"},
            {"label":"HTTP methods", "expr":"unique:method"},
        ],
        charts=[
            {"kind":"donut+hbar", "title":"severity", "color":"severity",
             "field":"severity"},
            {"kind":"hbar", "title":"per CWE", "field":"cwe", "span":2},
        ],
        table=[
            {"title":"Issue", "field":"name", "kind":"wrap-bold"},
            {"title":"Sev", "field":"severity", "kind":"badge-sev"},
            {"title":"CWE", "field":"cwe", "kind":"cwe"},
            {"title":"Method", "field":"method", "kind":"mono"},
            {"title":"URL", "field":"url", "kind":"pkg"},
            {"title":"Description", "field":"description", "kind":"wrap-muted"},
        ],
        sort_by="severity",
    ),
    "yara": _spec("yara",
        sev_field=None,
        cards=[
            {"label":"matches", "expr":"count"},
            {"label":"rules fired", "expr":"unique:rule"},
            {"label":"unique files", "expr":"unique:path"},
            {"label":"targets with hits", "expr":"unique:target"},
        ],
        charts=[
            {"kind":"donut+hbar", "title":"per rule", "color":"hash", "field":"rule"},
            {"kind":"stacked", "title":"rule × target", "color":"hash", "field":"rule",
             "span":2},
        ],
        table=[
            {"title":"Rule", "field":"rule", "kind":"cve"},
            {"title":"Target", "field":"target", "kind":"plain"},
            {"title":"File", "field":"path", "kind":"pkg"},
        ],
        sort_by="rule",
    ),
    "retire": _spec("retire",
        sev_field="severity",
        sev_order=["critical","high","medium","low","info"],
        sev_palette={"critical":"#7f1d1d","high":"#b91c1c","medium":"#b45309",
                     "low":"#0d6e3e","info":"#1d4ed8"},
        cards=[
            {"label":"JS vulns", "expr":"count"},
            {"label":"unique components", "expr":"unique:component"},
            {"label":"JS files", "expr":"unique:file"},
            {"label":"distinct CVEs", "expr":"uniqueNonEmpty:cve"},
        ],
        charts=[
            {"kind":"donut+hbar", "title":"severity", "color":"severity",
             "field":"severity"},
            {"kind":"hbar", "title":"top vulnerable libs", "field":"comp_ver", "limit":12},
            {"kind":"stacked", "title":"severity × target", "color":"severity",
             "field":"severity"},
        ],
        table=[
            {"title":"Lib", "field":"component", "kind":"pkg-bold"},
            {"title":"Version", "field":"version", "kind":"mono"},
            {"title":"Sev", "field":"severity", "kind":"badge-sev"},
            {"title":"CVE", "field":"cve", "kind":"cve"},
            {"title":"File", "field":"file", "kind":"pkg"},
            {"title":"Summary", "field":"summary", "kind":"wrap"},
            {"title":"Target", "field":"target", "kind":"plain"},
        ],
        sort_by="severity",
    ),
    "testssl": _spec("testssl",
        sev_field="severity",
        sev_order=["critical","high","medium","low","warn","info","ok"],
        sev_palette={"critical":"#7f1d1d","high":"#b91c1c","medium":"#b45309",
                     "low":"#0d6e3e","warn":"#b45309","info":"#1d4ed8","ok":"#0d6e3e"},
        cards=[
            {"label":"TLS findings", "expr":"count"},
            {"label":"distinct severities", "expr":"unique:severity"},
            {"label":"endpoints", "expr":"unique_pair:ip,port"},
        ],
        callout="The bench targets run plain HTTP. testssl detects 'no TLS' as a WARN — a valid finding, but it indicates that the bench scenario does not exercise the scanner. On real HTTPS targets we expect dozens of findings (weak ciphers, missing HSTS, etc.).",
        charts=[
            {"kind":"donut+hbar", "title":"severity", "color":"severity",
             "field":"severity", "span":3},
        ],
        table=[
            {"title":"ID", "field":"id", "kind":"cve"},
            {"title":"Sev", "field":"severity", "kind":"badge-sev"},
            {"title":"Endpoint", "field":"ip_port", "kind":"mono"},
            {"title":"Finding", "field":"finding", "kind":"wrap"},
            {"title":"Target", "field":"target", "kind":"plain"},
        ],
        sort_by="severity",
    ),
    "hadolint": _spec("hadolint",
        sev_field="level",
        sev_order=["error","warning","info","style"],
        sev_palette={"error":"#b91c1c","warning":"#b45309","info":"#1d4ed8","style":"#6b7280"},
        cards=[
            {"label":"warnings", "expr":"count"},
            {"label":"unique codes", "expr":"unique:code"},
            {"label":"distinct levels", "expr":"unique:level"},
        ],
        empty_msg="Hadolint returned no findings. The Dockerfile is reconstructed via <code>docker history --no-trunc</code> and loses COPY/ADD targets — limited analysis.",
        charts=[
            {"kind":"donut+hbar", "title":"level", "color":"severity", "field":"level"},
            {"kind":"hbar", "title":"fired codes", "field":"code", "span":2},
        ],
        table=[
            {"title":"Code", "field":"code", "kind":"cve"},
            {"title":"Level", "field":"level", "kind":"badge-sev"},
            {"title":"Line", "field":"line", "kind":"num"},
            {"title":"Message", "field":"message", "kind":"wrap"},
            {"title":"Target", "field":"target", "kind":"plain"},
        ],
    ),
    "httpx": _spec("httpx",
        sev_field=None,
        cards=[
            {"label":"responding endpoints", "expr":"count"},
            {"label":"unique servers", "expr":"uniqueNonEmpty:server"},
            {"label":"TLS detected", "expr":"countEq:tls_grab:yes"},
        ],
        cards_per_finding=[
            "URL: {url}", "Status: {status_code} · TLS: {tls_grab} · scheme: {scheme}",
            "Server: {server}", "Title: {title}", "Tech: {tech}",
            "Content-Type: {content_type}",
        ],
        callout="httpx only ran against juice-shop in this bench — the node2 target did not have juice-shop up when the phase-3 dynamics fired.",
        charts=[],
        table=[
            {"title":"Target", "field":"target", "kind":"plain"},
            {"title":"URL", "field":"url", "kind":"pkg"},
            {"title":"Status", "field":"status_code", "kind":"num"},
            {"title":"Server", "field":"server", "kind":"mono"},
            {"title":"Tech", "field":"tech", "kind":"wrap"},
        ],
    ),
    "whispers": _spec("whispers",
        sev_field="severity",
        sev_order=["critical","high","medium","low","info","ok"],
        sev_palette={"critical":"#7f1d1d","high":"#b91c1c","medium":"#b45309",
                     "low":"#0d6e3e","info":"#1d4ed8","ok":"#94a3b8"},
        cards=[
            {"label":"findings", "expr":"count", "sub":"parser for structured configs"},
            {"label":"unique rules", "expr":"unique:rule_id"},
            {"label":"unique files", "expr":"unique:file"},
            {"label":"unique keys", "expr":"unique:key"},
        ],
        charts=[
            {"kind":"donut+hbar", "title":"severity", "color":"severity",
             "field":"severity"},
            {"kind":"hbar", "title":"top 10 rules", "field":"rule_id", "limit":10},
            {"kind":"stacked", "title":"severity × target", "color":"severity",
             "field":"severity"},
        ],
        table=[
            {"title":"Rule", "field":"rule_id", "kind":"cve"},
            {"title":"Sev", "field":"severity", "kind":"badge-sev"},
            {"title":"Key", "field":"key", "kind":"pkg"},
            {"title":"Value", "field":"value", "kind":"mono-muted"},
            {"title":"File", "field":"file", "kind":"pkg"},
            {"title":"Line", "field":"line", "kind":"num"},
            {"title":"Target", "field":"target", "kind":"plain"},
        ],
        row_limit=1000,
    ),
    "jaeles": _spec("jaeles", broken=True),
    "cdxgen": _spec("cdxgen", broken=True),
    "clair": _spec("clair", broken=True),
    "dependency-check": _spec("dependency-check", broken=True),
    "govulncheck": _spec("govulncheck", broken=True),
    "guarddog": _spec("guarddog", broken=True),
    "kube-linter": _spec("kube-linter", broken=True),
    "pip-audit": _spec("pip-audit", broken=True),
    "secretscanner": _spec("secretscanner", broken=True),
}


# ─── JS engine (single universal renderer) ──────────────────────────────────

JS_ENGINE = r"""
// Universal scanner renderer — reads VIZ_SPECS + DETAIL and produces cards,
// donut/stacked/hbar charts and a table. Replaces N hand-written render
// functions with one declarative spec table.

function _esc(s) {
  return (s == null ? '' : String(s)).replace(/[&<>"']/g, c => (
    {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

const SEV_PALETTE_DEFAULT = {
  critical:'#7f1d1d', high:'#b91c1c', medium:'#b45309',
  low:'#0d6e3e', info:'#1d4ed8', warn:'#b45309', log:'#6b7280', error:'#b91c1c',
};
const ECO_PALETTE = {
  npm:'#cb3837', PyPI:'#3776ab', Maven:'#c71a36', 'Go':'#00add8',
  RubyGems:'#cc342d', NuGet:'#004880', Alpine:'#0d597f', Debian:'#a81d33',
  Ubuntu:'#e95420', crates:'#dea584', Hex:'#6e4a7e',
};

function _hashColor(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  const hue = Math.abs(h) % 360;
  return `hsl(${hue}, 55%, 45%)`;
}

function _colorFor(spec, chart, label) {
  const c = chart && chart.color;
  if (c === 'severity') return (spec.sev_palette || SEV_PALETTE_DEFAULT)[label]
                            || SEV_PALETTE_DEFAULT[(label||'').toLowerCase()]
                            || '#94a3b8';
  if (c === 'eco') return ECO_PALETTE[label] || _hashColor(label || '');
  if (c === 'target' || c === 'hash') return _hashColor(label || '');
  return c || 'var(--accent)';
}

function _evalCard(expr, f) {
  const [op, ...rest] = expr.split(':');
  const arg = rest.join(':');
  switch (op) {
    case 'count':           return fmtInt(f.length);
    case 'unique':          return fmtInt(new Set(f.map(x => x[arg])).size);
    case 'uniqueNonEmpty':  return fmtInt(new Set(f.filter(x=>x[arg]).map(x=>x[arg])).size);
    case 'unique_pair':     {
      const [a,b] = arg.split(',');
      return new Set(f.map(x=>x[a])).size + ' / ' + new Set(f.map(x=>x[b])).size;
    }
    case 'pct_unique':      return ((new Set(f.map(x=>x[arg])).size/f.length*100).toFixed(0)+'%');
    case 'max':             { const v = Math.max(0, ...f.map(x=>x[arg]||0)); return v ? v.toFixed(1) : '—'; }
    case 'avg':             { const a = f.map(x=>x[arg]).filter(v=>v); return a.length ? (a.reduce((s,x)=>s+x,0)/a.length).toFixed(1) : '—'; }
    case 'countNonEmpty':   return fmtInt(f.filter(x => x[arg] && x[arg].length).length);
    case 'pctNonEmpty':     return (f.filter(x=>x[arg]&&x[arg].length).length/f.length*100).toFixed(0)+'%';
    case 'countTrue':       return fmtInt(f.filter(x => x[arg]).length);
    case 'countEq':         { const [k,v] = arg.split(':'); return fmtInt(f.filter(x=>x[k]==v).length); }
    case 'countGte':        { const [k,v] = arg.split(':'); return fmtInt(f.filter(x=>(x[k]||0)>=parseFloat(v)).length); }
    case 'pctGte':          { const [k,v] = arg.split(':'); return (f.filter(x=>(x[k]||0)>=parseFloat(v)).length/f.length*100).toFixed(0)+'%'; }
  }
  return '—';
}

function _enrich(f, spec) {
  // Compute synthetic fields used by some specs
  return f.map(x => {
    const e = {...x};
    if (x.pkg && x.ecosystem) e.pkg_eco = `${x.pkg} (${x.ecosystem})`;
    if (x.component && x.version) e.comp_ver = `${x.component}@${x.version}`;
    if (x.ip != null && x.port != null) e.ip_port = `${x.ip}:${x.port}`;
    return e;
  });
}

function _groupBy(f, field, limit=0) {
  const m = {};
  for (const x of f) {
    const k = x[field];
    if (k == null || k === '') continue;
    m[k] = (m[k] || 0) + 1;
  }
  let arr = Object.entries(m).sort((a,b)=>b[1]-a[1])
              .map(([label,count])=>({label,count}));
  if (limit > 0) arr = arr.slice(0, limit);
  return arr;
}

function _renderDonutHbar(spec, f, chart) {
  const items = _groupBy(f, chart.field, chart.limit || 0);
  const total = items.reduce((s,x)=>s+x.count, 0);
  const order = chart.order || items.map(x => x.label);
  const colored = order.map(lbl => {
    const it = items.find(x => x.label === lbl);
    return it ? {...it, color: _colorFor(spec, chart, lbl)} : null;
  }).filter(Boolean);
  const donut = total > 0 ? donut2(colored, total, 140, chart.title) : '';
  return `<div class="chart-card"${chart.span?' style="grid-column:span '+chart.span+'"':''}>
    <h4>${chart.title}</h4>
    <div style="display:flex;align-items:center;gap:18px">
      ${donut}
      <div style="flex:1">${_renderHbarItems(colored)}</div>
    </div>
  </div>`;
}

function _renderHbar(spec, f, chart) {
  const items = _groupBy(f, chart.field, chart.limit || 0)
                  .map(x => ({...x, color: _colorFor(spec, chart, x.label)}));
  return `<div class="chart-card"${chart.span?' style="grid-column:span '+chart.span+'"':''}>
    <h4>${chart.title}</h4>${_renderHbarItems(items)}
  </div>`;
}

function _renderHbarItems(items) {
  if (!items.length) return '<p style="color:var(--muted-2);font-size:13px">no data</p>';
  const max = Math.max(...items.map(i=>i.count||0));
  return items.map(i => `<div class="hbar"><span class="lbl" title="${(i.label||'').replace(/"/g,'&quot;')}">${_esc(i.label||'')}</span><div class="bar"><span style="width:${max?(i.count/max*100):0}%; background:${i.color||'var(--accent)'}"></span></div><span class="num">${fmtInt(i.count||0)}</span></div>`).join('');
}

function _renderStacked(spec, f, chart) {
  const targets = (DETAIL[spec.scanner] && DETAIL[spec.scanner].meta.targets) || ['webgoat','dvwa','juice-shop'];
  const byT = {};
  for (const t of targets) byT[t] = {};
  for (const v of f) {
    const tgt = v.target;
    if (!byT[tgt]) continue;
    const k = v[chart.field] || '—';
    byT[tgt][k] = (byT[tgt][k] || 0) + 1;
  }
  const allKeys = new Set();
  for (const t of targets) for (const k of Object.keys(byT[t])) allKeys.add(k);
  const orderedKeys = (chart.order && chart.order.length)
    ? chart.order.filter(k => allKeys.has(k)).concat([...allKeys].filter(k => !chart.order.includes(k)))
    : [...allKeys];
  const rows = targets.map(t => {
    const tot = Object.values(byT[t]).reduce((a,b)=>a+b,0);
    if (tot === 0) return `<div class="sm-bar"><span class="target">${t}</span><div class="stack" style="background:#f3f4f6;height:14px;border-radius:3px"></div><span class="total">0</span></div>`;
    const segs = orderedKeys.map(k => {
      const n = byT[t][k] || 0;
      return n ? `<span style="width:${(n/tot*100).toFixed(2)}%;background:${_colorFor(spec, chart, k)};display:inline-block;height:100%" title="${_esc(k)}: ${n}"></span>` : '';
    }).join('');
    return `<div class="sm-bar"><span class="target">${t}</span><div class="stack" style="height:14px;display:flex;border-radius:3px;overflow:hidden">${segs}</div><span class="total">${fmtInt(tot)}</span></div>`;
  }).join('');
  return `<div class="chart-card"${chart.span?' style="grid-column:span '+chart.span+'"':''}><h4>${chart.title}</h4>${rows}</div>`;
}

function _renderCvssBins(spec, f, chart) {
  const bins = [0,0,0,0,0];
  const labels = ['0-3 (low)','3-5 (medium-low)','5-7 (medium)','7-9 (high)','9+ (critical)'];
  const colors = ['#94a3b8','#0d6e3e','#b45309','#b91c1c','#7f1d1d'];
  for (const x of f) {
    const v = x[chart.field] || 0;
    if (v >= 9) bins[4]++;
    else if (v >= 7) bins[3]++;
    else if (v >= 5) bins[2]++;
    else if (v >= 3) bins[1]++;
    else if (v > 0) bins[0]++;
  }
  const items = bins.map((c,i) => ({label: labels[i], count: c, color: colors[i]}));
  return `<div class="chart-card"${chart.span?' style="grid-column:span '+chart.span+'"':''}><h4>${chart.title}</h4>${_renderHbarItems(items)}</div>`;
}

function _renderChart(spec, f, chart) {
  switch (chart.kind) {
    case 'donut+hbar': return _renderDonutHbar(spec, f, chart);
    case 'hbar':       return _renderHbar(spec, f, chart);
    case 'stacked':    return _renderStacked(spec, f, chart);
    case 'cvss-bins':  return _renderCvssBins(spec, f, chart);
  }
  return '';
}

function _renderCards(spec, f) {
  return '<div class="cards">' + spec.cards.map(c => {
    const v = _evalCard(c.expr, f);
    let sub = c.sub || '';
    if (c.sub_expr) sub = (c.sub_prefix||'') + _evalCard(c.sub_expr, f) + (c.sub_suffix||'');
    const accent = c.accent ? ` style="border-left:4px solid ${c.accent}"` : '';
    const valStyle = c.accent ? ` style="color:${c.accent}"` : '';
    return `<div class="card"${accent}><div class="label">${c.label}</div><div class="value mono"${valStyle}>${v}</div>${sub?`<div class="sub">${sub}</div>`:''}</div>`;
  }).join('') + '</div>';
}

function _cellRender(col, row, spec) {
  const v = row[col.field];
  switch (col.kind) {
    case 'badge-sev': {
      const c = (spec.sev_palette || SEV_PALETTE_DEFAULT)[v] ||
                SEV_PALETTE_DEFAULT[(v||'').toLowerCase()] || '#6b7280';
      return `<td><span class="badge" style="background:${c}1a;color:${c}">${_esc(v||'?')}</span></td>`;
    }
    case 'cve':  return `<td><span class="cve">${_esc(v||'—')}</span></td>`;
    case 'cwe':  return `<td>${v ? `<span class="cve">CWE-${_esc(v)}</span>` : '—'}</td>`;
    case 'pkg':  return `<td><span class="pkg" style="font-size:11.5px">${_esc(v||'—')}</span></td>`;
    case 'pkg-bold': return `<td><strong class="pkg">${_esc(v||'')}</strong></td>`;
    case 'mono': return `<td><span class="mono">${_esc(v||'')}</span></td>`;
    case 'mono-muted': return `<td><span class="mono" style="font-size:11.5px;color:var(--muted)">${_esc(v||'')}</span></td>`;
    case 'wrap': return `<td><span class="title" style="white-space:normal">${_esc(v||'—')}</span></td>`;
    case 'wrap-bold': return `<td><span class="title" style="white-space:normal"><strong>${_esc(v||'')}</strong></span></td>`;
    case 'wrap-muted': return `<td><span class="title" style="white-space:normal;font-size:12px;color:var(--muted)">${_esc(v||'')}</span></td>`;
    case 'num':  return `<td class="num">${v != null ? fmtInt(v) : '—'}</td>`;
    case 'num1': return `<td class="num">${v ? Number(v).toFixed(1) : '—'}</td>`;
    case 'qod':  return `<td class="num">${v ? v+'%' : '—'}</td>`;
    case 'tag':  return `<td><span class="tag">${_esc(v||'')}</span></td>`;
    case 'tag-eco': return `<td><span class="tag static" style="font-size:11px;background:${_colorFor(spec, {color:'eco'}, v)}1a">${_esc(v||'')}</span></td>`;
    case 'badge': return `<td><span class="badge">${_esc(v||'')}</span></td>`;
    case 'bool': return `<td>${v ? '<b style="color:var(--err)">yes</b>' : 'no'}</td>`;
    default:     return `<td>${_esc(v||'—')}</td>`;
  }
}

function _renderTable(spec, f) {
  if (!spec.table || !spec.table.length) return '';
  const sortBy = (spec.sort_by || '').split(':');
  let rows = [...f];
  if (sortBy[0] && spec.sev_order && spec.sev_field === sortBy[0]) {
    const rank = Object.fromEntries(spec.sev_order.map((s,i)=>[s,i]));
    rows.sort((a,b) => (rank[a[sortBy[0]]] ?? 99) - (rank[b[sortBy[0]]] ?? 99));
  } else if (sortBy[0]) {
    const desc = sortBy[1] === 'desc';
    rows.sort((a,b) => {
      const va = a[sortBy[0]], vb = b[sortBy[0]];
      if (typeof va === 'number') return desc ? vb-va : va-vb;
      return desc ? String(vb).localeCompare(String(va)) : String(va).localeCompare(String(vb));
    });
  }
  const limit = spec.row_limit || 0;
  const limited = limit > 0 ? rows.slice(0, limit) : rows;
  const head = spec.table.map(c => `<th>${_esc(c.title)}</th>`).join('');
  const body = limited.map(r => '<tr>' +
    spec.table.map(c => _cellRender(c, r, spec)).join('') + '</tr>').join('');
  let html = `<h4 style="font-size:14px;margin:24px 0 10px;color:var(--muted);text-transform:uppercase;letter-spacing:0.04em">Full table</h4>
    <div class="tbl-wrap"><table class="tbl"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
  if (limit > 0 && rows.length > limit) {
    html += `<div class="tbl-pager">showing ${fmtInt(limit)} of ${fmtInt(rows.length)}${sortBy[0]?' (sorted by '+sortBy[0]+')':''}</div>`;
  }
  return html;
}

function _renderBroken(name) {
  const wrapperHints = {
    'jaeles':           'Jaeles expected: <code>juice-shop-jaeles.json</code> with <code>vuln_url</code> keys. Actual output: empty.',
    'cdxgen':           'cdxgen expected: <code>juice-shop-cdxgen.cdx.json</code> (CycloneDX SBOM). Actual output: empty directory.',
    'clair':            'Clair expected: <code>juice-shop-clair.json</code>. Actual output: empty (CVE DB did not download).',
    'dependency-check': 'OWASP DepCheck expected: <code>dependency-check-report.json/html/sarif</code>. Actual output: empty.',
    'govulncheck':      'govulncheck only runs against Go binaries with BuildInfo (Go 1.18+). Empty output: no valid Go binary (targets: Node, PHP, Java).',
    'guarddog':         'GuardDog expected: <code>juice-shop-guarddog.jsonl</code>. Empty file: no typosquatting/install scripts.',
    'kube-linter':      'kube-linter expected: <code>juice-shop-kube-linter.json</code>. No K8s YAML in the targets.',
    'pip-audit':        'pip-audit expected: <code>juice-shop-pip-audit.json</code>. No requirements.txt in the targets.',
    'secretscanner':    'Deepfence SecretScanner fails with <code>Illegal instruction</code> on CPUs without AVX2.',
  };
  return `<div class="cards">
    <div class="card" style="grid-column:span 3;text-align:left;background:#fffbeb;border-color:#fde68a">
      <div class="label" style="color:#92400e">Docker wrapper exited 0 — no artifacts in the directory</div>
      <div style="font-size:13px;line-height:1.6;margin-top:10px;color:#78350f">
        ${wrapperHints[name] || ''}<br><br>
        <strong>Recorded status:</strong> <code>ok</code> in metrics.json (the Python wrapper does not distinguish exit-0-with-empty-output from exit-0-with-output-present).
      </div>
    </div>
  </div>`;
}

function renderScanner(name) {
  const D = (DETAIL || {})[name];
  const root = document.getElementById('tab-' + name);
  const spec = (window.VIZ_SPECS || {})[name];
  if (!root || !spec) return;
  if (spec.broken) { root.insertAdjacentHTML('beforeend', _renderBroken(name)); return; }
  const f = _enrich((D && D.findings) || [], spec);
  if (!f.length) {
    const msg = spec.empty_msg || 'The scanner ran but <strong>returned no findings</strong> on the 3 bench targets.';
    root.insertAdjacentHTML('beforeend', `<div class="placeholder">${msg}</div>`);
    return;
  }
  let html = _renderCards(spec, f);
  if (spec.callout) html += `<div class="placeholder" style="margin-top:14px">${spec.callout}</div>`;
  if (spec.charts && spec.charts.length) {
    // Group charts into rows of 3 (with optional span overrides)
    let row = '<div class="chart-row" style="margin-top:18px">', span = 0;
    for (const c of spec.charts) {
      const cspan = c.span || 1;
      if (span + cspan > 3 && span > 0) { html += row + '</div>'; row = '<div class="chart-row" style="margin-top:14px">'; span = 0; }
      row += _renderChart(spec, f, c);
      span += cspan;
    }
    if (span > 0) html += row + '</div>';
  }
  html += _renderTable(spec, f);
  root.insertAdjacentHTML('beforeend', html);
}

// donut2 — uses existing donut() if present, falls back gracefully
function donut2(parts, total, size, label) {
  return (typeof donut === 'function') ? donut(parts, total, size, label) :
    `<svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}"></svg>`;
}
"""

CLICK_HANDLER_BLOCK = """[
      'arachni','cdxgen','checkov','clair','dependency-check','detect-secrets',
      'govulncheck','guarddog','hadolint','httpx','jaeles','kube-linter',
      'openvas','osv','pip-audit','retire','secretscanner','testssl',
      'whispers','yara',
    ].forEach(s => {
      if (ctrl === 'tab-'+s && !window['_'+s+'Rendered']) { renderScanner(s); window['_'+s+'Rendered'] = true; }
    });"""


def main():
    content = HTML.read_text(encoding="utf-8")
    detail = json.loads(DETAIL_JSON.read_text(encoding="utf-8"))

    # 1) Merge DETAIL
    m = re.search(r"const DETAIL = (\{.*?\});\n", content, flags=re.S)
    if not m:
        raise RuntimeError("DETAIL = {...} not found")
    existing = json.loads(m.group(1))
    existing.update(detail)
    content = (content[:m.start()] + f"const DETAIL = {json.dumps(existing, ensure_ascii=False)};\n"
               + content[m.end():])

    # 2) Strip any previous Phase-2/3 renderer block (between sentinel comments)
    content = re.sub(r"// ────────── Phase-2/3 scanner renderers ──────────.*?(?=\nfunction renderSimple)",
                     "", content, count=1, flags=re.S)

    # 3) Inject the universal engine + VIZ_SPECS + click dispatcher
    specs_js = "window.VIZ_SPECS = " + json.dumps(VIZ_SPECS, ensure_ascii=False) + ";"
    block = "// ────────── Phase-2/3 scanner renderers ──────────\n" + specs_js + "\n" + JS_ENGINE
    anchor = "function renderSimple(name) {"
    content = content.replace(anchor, block + "\n\n" + anchor, 1)

    # 4) Strip openvas from legacy renderSimple lists (both forEach occurrences)
    content = content.replace("'whatweb','openvas'].forEach(s =>", "'whatweb'].forEach(s =>")

    # 5) Insert single click dispatcher (idempotent — skip if present)
    legacy_close = ("['gitleaks','clamav','nmap','nikto','wapiti','sqlmap',"
                    "'whatweb'].forEach(s => {\n"
                    "      if (ctrl === 'tab-'+s && !window['_'+s+'Rendered']) "
                    "{ renderSimple(s); window['_'+s+'Rendered'] = true; }\n"
                    "    });")
    if "renderScanner(s)" not in content and legacy_close in content:
        content = content.replace(legacy_close,
                                  legacy_close + "\n    " + CLICK_HANDLER_BLOCK, 1)

    # 6) Init dispatcher (page-load) — same set
    init_close = ("['gitleaks','clamav','nmap','nikto','wapiti','sqlmap',"
                  "'whatweb'].forEach(s => {\n"
                  "    if (DETAIL && DETAIL[s]) { renderSimple(s); window['_'+s+'Rendered'] = true; }\n"
                  "  });")
    init_block = """[
    'arachni','cdxgen','checkov','clair','dependency-check','detect-secrets',
    'govulncheck','guarddog','hadolint','httpx','jaeles','kube-linter',
    'openvas','osv','pip-audit','retire','secretscanner','testssl',
    'whispers','yara',
  ].forEach(s => {
    if (DETAIL && DETAIL[s] && !window['_'+s+'Rendered']) { renderScanner(s); window['_'+s+'Rendered'] = true; }
  });"""
    if "renderScanner" in content and init_close in content and \
       content.count("renderScanner(s)") < 2:
        content = content.replace(init_close,
                                  init_close + "\n  " + init_block, 1)

    HTML.write_text(content, encoding="utf-8")
    print(f"wrote {HTML.relative_to(ROOT)} ({len(content):,} chars)")


if __name__ == "__main__":
    main()
