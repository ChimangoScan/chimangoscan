#!/usr/bin/env python3
"""Generate a consolidated comparison report for the phase-2 and phase-3
scanners that aren't covered by the original scanner-comparison.html.

Walks reports/scans-output/{node2,node1}/<target>/<scanner>/ for raw outputs
and reads the metrics.json files written by the scans pipeline. Emits a
single self-contained HTML at reports/scanner-comparison-new.html.

Run from the repo root:
    python3 scripts/build_new_scanners_report.py
"""
from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SCANS_OUT = ROOT / "reports" / "scans-output"
OUT_HTML = ROOT / "reports" / "scanner-comparison-new.html"

HOSTS = ["node2", "node1"]
TARGETS = ["juice-shop", "dvwa", "webgoat"]

# Scanners covered by the ORIGINAL scanner-comparison.html (excluded here).
ORIGINAL_SCANNERS = {
    "syft", "trivy", "grype", "dockle", "trufflehog", "gitleaks", "clamav",
    "whatweb", "nmap", "nikto", "nuclei", "wapiti", "zap", "sqlmap",
}

# Per-scanner descriptions surfaced in the right-side panel.
SCANNER_INFO: dict[str, dict[str, str]] = {
    "osv":              {"phase": "2", "category": "vuln-cve", "tagline": "OSV.dev DB matcher (Google).",
                         "why":     "Aggregates ecosystem-native advisories that NVD lags on (Go, Rust, Cargo)."},
    "secretscanner":    {"phase": "2", "category": "secrets", "tagline": "Deepfence container-native secret scanner.",
                         "why":     "~140 YARA-style rules tuned for container artefacts."},
    "yara":             {"phase": "2", "category": "malware", "tagline": "Generic rule engine for binaries/text.",
                         "why":     "Custom rules for crypto-miners, reverse shells, embedded private keys."},
    "detect-secrets":   {"phase": "2", "category": "secrets", "tagline": "Yelp baseline-diffable secret scanner.",
                         "why":     "Baseline-based — flag only NEW secrets across reruns."},
    "guarddog":         {"phase": "2", "category": "supply-chain", "tagline": "Datadog supply-chain malice analyser.",
                         "why":     "Catches typosquatting, install scripts, exfil patterns."},
    "govulncheck":      {"phase": "2", "category": "vuln-go", "tagline": "Reachability-aware Go CVE scanner.",
                         "why":     "Reports CVEs only when the vulnerable function is reachable."},
    "clair":            {"phase": "2", "category": "vuln-cve", "tagline": "Quay/Red Hat layer-indexed scanner.",
                         "why":     "Layer-by-layer CVE matching, third opinion vs Trivy/Grype."},
    "dependency-check": {"phase": "2", "category": "vuln-cve", "tagline": "OWASP CPE-based correlation engine.",
                         "why":     "Strong on Maven/Gradle; NVD + OSS Index dual-feed."},
    "cdxgen":           {"phase": "2", "category": "sbom", "tagline": "OWASP CycloneDX 1.5 SBOM generator.",
                         "why":     "Deeper monorepo coverage than Syft (Maven/Gradle/Bazel)."},
    "retire":           {"phase": "2", "category": "vuln-js", "tagline": "JS library hash/version scanner.",
                         "why":     "Catches CDN-vendored JS that package.json scanners miss."},
    "whispers":         {"phase": "2", "category": "secrets", "tagline": "Structured-config secret parser.",
                         "why":     "Parses YAML/JSON/Dockerfile keys (`password:`, `api_key:`)."},
    "kube-linter":      {"phase": "2", "category": "k8s", "tagline": "StackRox K8s manifest linter.",
                         "why":     "Audits bundled Helm/manifests for security best practices."},
    "hadolint":         {"phase": "3", "category": "dockerfile", "tagline": "Dockerfile linter (alt to dockle).",
                         "why":     "Reconstructs Dockerfile from layer history, runs shellcheck on RUN."},
    "checkov":          {"phase": "3", "category": "iac", "tagline": "Bridgecrew IaC misconfig analyser.",
                         "why":     "1000+ policies across IaC formats — alt to trivy --scanners config."},
    "pip-audit":        {"phase": "3", "category": "vuln-py", "tagline": "PyPA Python advisory DB scanner.",
                         "why":     "Authoritative per-ecosystem alt to Trivy/Grype on Python."},
    "httpx":            {"phase": "3", "category": "web-recon", "tagline": "ProjectDiscovery web fingerprint.",
                         "why":     "TLS/JARM/CDN + redirects — alt to whatweb."},
    "rustscan":         {"phase": "3", "category": "port-scan", "tagline": "Fast port sweep with nmap handoff.",
                         "why":     "65k-port discovery in ms, then nmap for service detection."},
    "jaeles":           {"phase": "3", "category": "dast", "tagline": "Template-driven web vuln scanner.",
                         "why":     "Listed alongside Tsunami in the report (Tsunami's image is private)."},
    "tsunami":          {"phase": "3", "category": "dast", "tagline": "Google high-signal vuln scanner (skipped).",
                         "why":     "Image is gated behind a private GHCR — replaced with jaeles."},
    "arachni":          {"phase": "3", "category": "dast", "tagline": "Full Ruby DAST framework — alt to ZAP/Burp.",
                         "why":     "Independent SQLi/XSS/RFI/LFI checks; archived 2017 but plugins still useful as cross-validation."},
    "testssl":          {"phase": "3", "category": "tls", "tagline": "Comprehensive TLS/SSL audit.",
                         "why":     "Heartbleed/POODLE/cipher checks — orthogonal signal vs all HTTP-layer scanners."},
    "openvas":          {"phase": "1", "category": "network-vuln", "tagline": "Greenbone GVM full network scan.",
                         "why":     "100k+ NASL plugins; the original heavyweight reference."},
}


# ────────────────────────────────────────────────────────────────────────────
#  Findings count helpers — heuristics over each scanner's primary output
# ────────────────────────────────────────────────────────────────────────────

def _count_lines(p: Path) -> int:
    if not p.exists():
        return 0
    try:
        return sum(1 for ln in p.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip())
    except Exception:
        return 0


def _count_jsonl_records(p: Path) -> int:
    return _count_lines(p)


def _safe_json(p: Path) -> Any:
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace") or "null")
    except json.JSONDecodeError:
        return None


def count_findings(scanner: str, target: str, sdir: Path) -> int:
    """Best-effort findings count for each scanner's primary output."""
    if not sdir.exists():
        return 0
    p = lambda *names: next((sdir / n for n in names if (sdir / n).exists()), None)

    if scanner == "osv":
        f = p(f"{target}-osv.json")
        d = _safe_json(f) if f else None
        if isinstance(d, dict):
            return sum(len(r.get("packages", [])) for r in d.get("results", []))
    if scanner == "yara":
        f = p(f"{target}-yara.txt")
        return _count_lines(f) if f else 0
    if scanner == "detect-secrets":
        f = p(f"{target}-detect-secrets.json")
        d = _safe_json(f) if f else None
        if isinstance(d, dict):
            return sum(len(v) for v in (d.get("results") or {}).values())
    if scanner == "guarddog":
        f = p(f"{target}-guarddog.jsonl")
        return _count_jsonl_records(f) if f else 0
    if scanner == "govulncheck":
        f = p(f"{target}-govulncheck.json")
        d = _safe_json(f) if f else None
        if isinstance(d, list):
            return sum(1 for e in d if isinstance(e, dict) and "Vuln" in e)
        return _count_lines(f) // 5 if f else 0
    if scanner == "clair":
        f = p(f"{target}-clair.json")
        d = _safe_json(f) if f else None
        if isinstance(d, dict):
            return len(d.get("Vulnerabilities", []) or d.get("vulnerabilities", []))
    if scanner == "dependency-check":
        f = p("dependency-check-report.json")
        d = _safe_json(f) if f else None
        if isinstance(d, dict):
            return sum(len(dep.get("vulnerabilities", []))
                       for dep in d.get("dependencies", []))
    if scanner == "cdxgen":
        f = p(f"{target}-cdxgen.cdx.json")
        d = _safe_json(f) if f else None
        if isinstance(d, dict):
            return len(d.get("components", []))
    if scanner == "retire":
        f = p(f"{target}-retire.json")
        d = _safe_json(f) if f else None
        if isinstance(d, list):
            return sum(len(c.get("results", [])) for c in d)
    if scanner == "whispers":
        f = p(f"{target}-whispers.json")
        return _count_lines(f) if f else 0
    if scanner == "kube-linter":
        f = p(f"{target}-kube-linter.json")
        d = _safe_json(f) if f else None
        if isinstance(d, dict):
            return len(d.get("Reports", []) or d.get("reports", []))
    if scanner == "hadolint":
        f = p(f"{target}-hadolint.json")
        d = _safe_json(f) if f else None
        if isinstance(d, list):
            return len(d)
    if scanner == "checkov":
        f = p(f"{target}-checkov.json")
        d = _safe_json(f) if f else None
        if isinstance(d, dict):
            results = d.get("results") or {}
            return len(results.get("failed_checks", []))
        if isinstance(d, list):
            return sum(len((r.get("results") or {}).get("failed_checks", [])) for r in d)
    if scanner == "pip-audit":
        f = p(f"{target}-pip-audit.txt")
        if f:
            txt = f.read_text(encoding="utf-8", errors="replace")
            return len(re.findall(r"^\S+\s+[0-9]\S*\s+\S+", txt, re.M))
    if scanner == "httpx":
        f = p(f"{target}-httpx.jsonl")
        return _count_jsonl_records(f) if f else 0
    if scanner == "openvas":
        # XML report has <result_count><full>N</full></result_count>
        f = p(f"{target}-openvas.xml")
        if f:
            txt = f.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"<result_count>(\d+)", txt)
            if m:
                return int(m.group(1))
    if scanner == "arachni":
        f = p(f"{target}-arachni.json")
        d = _safe_json(f) if f else None
        if isinstance(d, dict):
            return len(d.get("issues", []))
    if scanner == "testssl":
        f = p(f"{target}-testssl.json")
        d = _safe_json(f) if f else None
        if isinstance(d, list):
            return len(d)
    if scanner == "jaeles":
        f = p(f"{target}-jaeles.json")
        if f and f.stat().st_size > 0:
            return f.read_text(encoding="utf-8").count('"vuln_url"')
    if scanner == "secretscanner":
        f = p(f"{target}-secretscanner.json")
        d = _safe_json(f) if f else None
        if isinstance(d, list):
            return len(d)
    return 0


# ────────────────────────────────────────────────────────────────────────────
#  Aggregation
# ────────────────────────────────────────────────────────────────────────────

def collect() -> dict[str, Any]:
    """Read metrics + findings, returning a flat dict keyed by (scanner,target)."""
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for host in HOSTS:
        for tgt in TARGETS:
            metrics_file = SCANS_OUT / host / tgt / f"{tgt}-metrics.json"
            if not metrics_file.exists():
                continue
            try:
                entries = json.loads(metrics_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            for e in entries:
                scanner = e.get("scanner")
                if not scanner or scanner in ORIGINAL_SCANNERS:
                    continue
                if scanner == "openvas" and host == "node2":
                    # The node2 OpenVAS attempt failed; node1 is authoritative.
                    continue
                sdir = SCANS_OUT / host / tgt / scanner
                key = (scanner, tgt)
                # Prefer the entry with status=ok; otherwise keep latest.
                if key in out and out[key]["status"] == "ok" and e.get("status") != "ok":
                    continue
                files = [f.name for f in sdir.glob("*") if f.is_file()] if sdir.exists() else []
                status = e.get("status", "unknown")
                # Mark scanners that "succeeded" but produced no artifact —
                # the wrapper exited zero but Docker dropped no files. This
                # affects dependency-check, clair, govulncheck, kube-linter
                # in some configurations.
                if status == "ok" and not files:
                    status = "ok (no output)"
                out[key] = {
                    "scanner": scanner,
                    "target": tgt,
                    "host": host,
                    "status": status,
                    "wall_seconds": e.get("wall_seconds", 0),
                    "peak_cpu_percent": e.get("peak_cpu_percent", 0),
                    "peak_mem_mb": e.get("peak_mem_mb", 0),
                    "block_read_mb": e.get("block_read_mb", 0),
                    "block_write_mb": e.get("block_write_mb", 0),
                    "findings": count_findings(scanner, tgt, sdir),
                    "files": files,
                }
    return out


# ────────────────────────────────────────────────────────────────────────────
#  HTML rendering
# ────────────────────────────────────────────────────────────────────────────

CSS = """
:root { --bg:#fafaf9; --panel:#fff; --border:#e7e5e4; --text:#1c1917;
        --muted:#57534e; --muted-2:#78716c; --accent:#7c3aed; --accent-bg:rgba(124,58,237,0.10);
        --ok:#15803d; --warn:#b45309; --err:#b91c1c; --t:0.15s; }
* { box-sizing:border-box; }
body { margin:0; padding:24px; font:14px/1.55 ui-sans-serif,system-ui,'Inter',sans-serif;
       color:var(--text); background:var(--bg); }
h1 { font:700 22px ui-sans-serif,system-ui; margin:0 0 8px; }
h2 { font:600 16px ui-sans-serif,system-ui; margin:24px 0 12px; }
.lead { color:var(--muted); margin:0 0 24px; }
.card { background:var(--panel); border:1px solid var(--border); border-radius:12px;
        padding:18px 20px; margin-bottom:16px; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--border); }
th { font-weight:600; color:var(--muted); background:#f5f5f4; position:sticky; top:0; }
td.num { text-align:right; font-variant-numeric:tabular-nums; }
.badge { display:inline-block; padding:2px 8px; border-radius:100px; font:600 11px ui-monospace,monospace;
         background:rgba(0,0,0,0.05); color:var(--muted); }
.badge.ok { background:rgba(21,128,61,0.10); color:var(--ok); }
.badge.err { background:rgba(185,28,28,0.10); color:var(--err); }
.badge.warn { background:rgba(180,83,9,0.10); color:var(--warn); }
.badge.phase2 { background:rgba(124,58,237,0.10); color:var(--accent); }
.badge.phase3 { background:rgba(180,83,9,0.10); color:var(--warn); }
.tag { padding:1px 7px; font:600 10px ui-monospace,monospace; border-radius:4px;
       background:rgba(0,0,0,0.04); color:var(--muted-2); }
.scanner-name { font-weight:600; font-family:ui-monospace,monospace; }
.muted { color:var(--muted); }
.mono { font-family:ui-monospace,monospace; font-size:12px; }
details { margin:6px 0; }
summary { cursor:pointer; padding:4px 0; }
.bar { height:6px; background:linear-gradient(to right,var(--accent),var(--accent));
       border-radius:3px; }
.bar-bg { background:#e7e5e4; height:6px; border-radius:3px; overflow:hidden; }
.legend { display:flex; gap:14px; margin:0 0 18px; flex-wrap:wrap; color:var(--muted); font-size:12px; }
"""


def render_summary_table(data: dict) -> str:
    """Scanner × target findings matrix."""
    scanners = sorted({k[0] for k in data}, key=lambda s: (
        SCANNER_INFO.get(s, {}).get("phase", "9"),
        SCANNER_INFO.get(s, {}).get("category", ""),
        s,
    ))
    rows = []
    for s in scanners:
        info = SCANNER_INFO.get(s, {})
        cells = [f'<td><span class="scanner-name">{html.escape(s)}</span> '
                 f'<span class="badge phase{info.get("phase","")}">P{info.get("phase","?")}</span> '
                 f'<span class="tag">{html.escape(info.get("category","-"))}</span></td>']
        for tgt in TARGETS:
            entry = data.get((s, tgt))
            if entry is None:
                cells.append('<td class="num muted">—</td>')
            else:
                status = entry["status"]
                badge_class = "ok" if status == "ok" else ("warn" if "no output" in status else "err")
                short_status = status[:8] + "…" if len(status) > 8 else status
                cells.append(
                    f'<td class="num">'
                    f'<strong>{entry["findings"]}</strong> '
                    f'<span class="muted">({entry["wall_seconds"]:.0f}s)</span><br>'
                    f'<span class="badge {badge_class}">{html.escape(short_status)}</span>'
                    f'</td>'
                )
        rows.append("<tr>" + "".join(cells) + "</tr>")
    header = "<tr><th>Scanner</th>" + "".join(f"<th>{t}</th>" for t in TARGETS) + "</tr>"
    return f'<table>{header}{"".join(rows)}</table>'


def render_metrics_table(data: dict) -> str:
    """Detailed runtime metrics for all entries."""
    rows = []
    for (s, t), e in sorted(data.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        rows.append(
            "<tr>"
            f'<td class="scanner-name">{html.escape(s)}</td>'
            f'<td>{html.escape(t)}</td>'
            f'<td>{html.escape(e["host"])}</td>'
            f'<td><span class="badge {"ok" if e["status"]=="ok" else ("warn" if "no output" in e["status"] else "err")}">{html.escape(e["status"][:24])}</span></td>'
            f'<td class="num">{e["wall_seconds"]:.1f}</td>'
            f'<td class="num">{e["peak_cpu_percent"]:.1f}</td>'
            f'<td class="num">{e["peak_mem_mb"]:.1f}</td>'
            f'<td class="num">{e["block_read_mb"]:.1f}</td>'
            f'<td class="num">{e["block_write_mb"]:.1f}</td>'
            f'<td class="num"><strong>{e["findings"]}</strong></td>'
            "</tr>"
        )
    header = ("<tr><th>Scanner</th><th>Target</th><th>Host</th><th>Status</th>"
              "<th>Wall (s)</th><th>CPU %</th><th>RAM (MB)</th>"
              "<th>Disk R (MB)</th><th>Disk W (MB)</th><th>Findings</th></tr>")
    return f'<table>{header}{"".join(rows)}</table>'


def render_per_scanner_panel(data: dict) -> str:
    """Per-scanner detail (description + per-target outputs)."""
    by_scanner: dict[str, list] = {}
    for (s, t), e in data.items():
        by_scanner.setdefault(s, []).append(e)
    blocks = []
    for s, entries in sorted(by_scanner.items()):
        info = SCANNER_INFO.get(s, {})
        targets_html = "".join(
            f'<li><strong>{html.escape(e["target"])}</strong> ({e["host"]}): '
            f'<span class="muted">{e["wall_seconds"]:.1f}s, '
            f'{e["peak_cpu_percent"]:.0f}% CPU, {e["peak_mem_mb"]:.0f} MB RAM</span> '
            f'→ <strong>{e["findings"]}</strong> findings, '
            f'<span class="badge {"ok" if e["status"]=="ok" else ("warn" if "no output" in e["status"] else "err")}">{html.escape(e["status"][:20])}</span>'
            f'<br><span class="mono muted">artefacts: {", ".join(html.escape(f) for f in e["files"][:6])}{("…" if len(e["files"])>6 else "")}</span>'
            "</li>"
            for e in sorted(entries, key=lambda x: x["target"])
        )
        blocks.append(
            f'<div class="card">'
            f'<h2><span class="scanner-name">{html.escape(s)}</span> '
            f'<span class="badge phase{info.get("phase","")}">P{info.get("phase","?")}</span> '
            f'<span class="tag">{html.escape(info.get("category","-"))}</span></h2>'
            f'<p class="lead">{html.escape(info.get("tagline","-"))}</p>'
            f'<p><strong>Why:</strong> {html.escape(info.get("why","-"))}</p>'
            f'<ul>{targets_html}</ul>'
            "</div>"
        )
    return "".join(blocks)


def render_html(data: dict) -> str:
    n_scanners = len({k[0] for k in data})
    ok_count = sum(1 for e in data.values() if e["status"] == "ok")
    fail_count = len(data) - ok_count
    total_findings = sum(e["findings"] for e in data.values())
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Scanner Comparison — phase 2 + phase 3</title>
<style>{CSS}</style></head><body>
<h1>Phase 2 + 3 scanner comparison</h1>
<p class="lead">A complement to <a href="scanner-comparison.html">scanner-comparison.html</a>.
Covers the <strong>{n_scanners} scanners</strong> added in phases 2 (12 scanners) and 3 (6 alternatives
suggested in the "Alternatives" panel) run against the 3 canonical targets
(juice-shop, dvwa, webgoat). Total runs: {len(data)} (ok={ok_count}, fail={fail_count}).
Total findings: <strong>{total_findings}</strong>. Generated on {ts}.</p>

<div class="legend">
  <span><span class="badge phase2">P2</span> phase 2 (12 scanners — unique signal vs. original)</span>
  <span><span class="badge phase3">P3</span> phase 3 (6 alternatives suggested in the panel)</span>
  <span><span class="badge ok">ok</span> success</span>
  <span><span class="badge err">error</span> failure</span>
</div>

<div class="card">
  <h2>Findings matrix</h2>
  {render_summary_table(data)}
</div>

<div class="card">
  <h2>Detailed metrics (wall time, CPU, RAM, disk)</h2>
  {render_metrics_table(data)}
</div>

<h2>Detalhes por scanner</h2>
{render_per_scanner_panel(data)}

<p class="muted" style="margin-top:32px;font-size:12px;">
Source: <code>reports/scans-output/{{node2,node1}}/&lt;target&gt;/&lt;scanner&gt;/</code> ·
Generator: <code>scripts/build_new_scanners_report.py</code>
</p>
</body></html>
"""


def main():
    data = collect()
    OUT_HTML.write_text(render_html(data), encoding="utf-8")
    print(f"wrote {OUT_HTML.relative_to(ROOT)} — {len(data)} entries, "
          f"{len({k[0] for k in data})} scanners, "
          f"{sum(e['findings'] for e in data.values())} total findings")


if __name__ == "__main__":
    main()
