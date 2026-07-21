#!/usr/bin/env python3
"""Single-shot, idempotent rebuilder for reports/scanner-comparison.html.

Two modes:
  - First run (no integration markers): re-run the legacy injector chain
    (integrate → patch → inject_renderers) which adds new scanner UI.
  - Subsequent runs: only refresh DATA and DETAIL literals from fresh
    scan-output. UI shape is preserved; data evolves.

Plus a slice-based (no-regex) text-block patcher for the high-risk multi-
line edits that destroyed the HTML when expressed as regex (lead text,
recommendations, caveats, openvas card). Slice-based is bounded and
explicit — if the start marker isn't found, it's a no-op rather than a
catastrophic match.

Usage:
    python3 scripts/rebuild_report.py              # rebuild full
    python3 scripts/rebuild_report.py --check      # validate only
    python3 scripts/rebuild_report.py --reset      # restore from .bak first
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTML = ROOT / "reports" / "scanner-comparison.html"
BAK = Path("/tmp/scanner-comparison.html.bak")
SCRIPTS = ROOT / "scripts"

# ─── Slice-based text-block updates ────────────────────────────────────────

def replace_between(content: str, start: str, end: str, new_body: str) -> tuple[str, bool]:
    """Replace text between two unique anchor strings (anchors preserved).

    Returns (new_content, replaced?). Safer than regex for large blocks: if
    either anchor isn't found, returns the content unchanged.
    """
    i = content.find(start)
    if i < 0:
        return content, False
    j = content.find(end, i + len(start))
    if j < 0:
        return content, False
    return content[:i + len(start)] + new_body + content[j:], True


def replace_text(content: str, old: str, new: str) -> tuple[str, bool]:
    """Replace a specific literal once. Returns (content, replaced?)."""
    if old not in content:
        return content, False
    return content.replace(old, new, 1), True


# ─── Per-block payloads ────────────────────────────────────────────────────

def _normalize_lead_and_badge(content: str) -> tuple[str, bool]:
    """Force lead text + 'Per scanner' badge to reflect 34 (current count)
    regardless of starting value (14, 33, 34 — all converge to 34)."""
    changed = False
    new = re.sub(r"Bench of \d+ scanners against 3 targets",
                 "Bench of 34 scanners against 3 targets", content, count=1)
    if new != content:
        changed = True
    content = new
    new = re.sub(r'(id="mt-scanner"[^>]*>Per scanner <span class="badge">)\d+(</span>)',
                 r'\g<1>34\g<2>', content, count=1)
    if new != content:
        changed = True
    return new, changed

OPENVAS_CARD_OLD_START = ('        <article class="scanner-card">\n'
                          '          <h4>openvas <span class="tag dynamic">dynamic</span> '
                          '<span class="tag warn">not run</span></h4>')
OPENVAS_CARD_OLD_END = "        </article>"
OPENVAS_CARD_NEW = """        <article class="scanner-card">
          <h4>openvas <span class="tag dynamic">dynamic</span></h4>
          <div class="meta">Network Vuln (NASL) · Greenbone · <a href="https://www.openvas.org/" target="_blank" rel="noopener">repo</a></div>
          <div class="stats"><div class="stat"><span class="v">39 min</span><span class="l">time</span></div><div class="stat"><span class="v">3.3 GB</span><span class="l">RAM</span></div><div class="stat"><span class="v">56</span><span class="l">findings</span></div></div>
          <p>Greenbone Vulnerability Manager. 100k+ NASL plugins. Open-source equivalent to Nessus. Run on juice-shop after 5 fix iterations (TLS, user gvm, dynamic port_list, NVT sync).</p>
          <p class="pros"><strong>+</strong> Immense coverage of CVEs in network services. 70 NVTs fired (severity 8.1).</p>
          <p class="cons"><strong>−</strong> Heavy setup: bootstrap + sync ~20 min. A full scan is ~39 min per target. Not scalable to 25,924 images without serious parallel orchestration.</p>
        </article>"""

# Recos block: anchor on the unique section id, replace its inner <div class="recos">.
RECOS_START = '<section id="recos">'
RECOS_END = '</section>\n\n<!-- ── Scanner catalog'
RECOS_NEW = """
  <h2>Recommended stacks for the paper</h2>
  <p class="lead">Decisions mapped to the ChimangoScan pipeline. Phases I (crawl) and II (layer graph) are already defined; these scanners feed phase III (analysis).</p>
  <div class="recos">
    <div class="reco">
      <h4>📦 Phase III-A — Static</h4>
      <p style="font-size:13px;color:var(--muted)">Filesystem-only, parallelizable. Amortizable across all 12 M crawled repos.</p>
      <ul>
        <li><strong>Syft</strong> — canonical SBOM</li>
        <li><strong>Grype + Trivy</strong> — primary + secondary CVE</li>
        <li><strong>OSV-Scanner</strong> ⭐ — ecosystem-native DB (Go/Rust/Cargo) — 1,240 orthogonal CVEs</li>
        <li><strong>TruffleHog</strong> — verified secrets</li>
        <li><strong>detect-secrets</strong> ⭐ — baseline-diffable (2,571 hits for tuning)</li>
        <li><strong>Dockle + Hadolint</strong> — CIS hardening + Dockerfile lint</li>
        <li><strong>Checkov</strong> ⭐ — IaC misconfig (24 failed checks)</li>
        <li><strong>retire.js</strong> ⭐ — vendored JS libs (47 vulns)</li>
      </ul>
    </div>
    <div class="reco">
      <h4>🌐 Phase III-B — Dynamic</h4>
      <p style="font-size:13px;color:var(--muted)">docker run + scan + docker rm. Apply to the ~25,924 high-impact ones.</p>
      <ul>
        <li><strong>Nmap + Nuclei + ZAP</strong> — port + templates + DAST</li>
        <li><strong>Arachni</strong> ⭐ — DAST cross-validation (5 independent issues)</li>
        <li><strong>OpenVAS</strong> ⭐ — now run: 56 findings on juice-shop (severity 8.1)</li>
        <li><strong>httpx</strong> ⭐ — lean recon (TLS/JARM/CDN)</li>
      </ul>
    </div>
    <div class="reco special">
      <h4>🦠 Specialized</h4>
      <p style="font-size:13px;color:var(--muted)">Apply where a static signal justifies it.</p>
      <ul>
        <li><strong>ClamAV + YARA</strong> ⭐ — signature + custom rules</li>
        <li><strong>SQLMap</strong> — only on already-flagged endpoints</li>
        <li><strong>testssl.sh</strong> ⭐ — when the target is HTTPS</li>
        <li><strong>govulncheck</strong> ⭐ — Go images</li>
        <li><strong>pip-audit</strong> ⭐ — Python images</li>
        <li><strong>kube-linter</strong> ⭐ — images with K8s manifests</li>
      </ul>
    </div>
    <div class="reco exclude">
      <h4>❌ Wrapper-broken / overlapping</h4>
      <p style="font-size:13px;color:var(--muted)">Cost &gt; benefit, or the wrapper needs rework.</p>
      <ul>
        <li><strong>Nikto/Wapiti/WhatWeb/GitLeaks</strong> — overlapping (keep as fallback)</li>
        <li><strong>SecretScanner</strong> — requires AVX2; fails on old CPUs</li>
        <li><strong>cdxgen, Clair, dependency-check, kube-linter, pip-audit, guarddog, jaeles</strong> — Docker wrapper exits 0 with no artifact</li>
        <li><strong>Tsunami</strong> — private GHCR image — replaced by Jaeles</li>
      </ul>
    </div>
  </div>
"""

# Caveats: anchor on the unique section id.
CAVEATS_START = '<section id="caveats">'
CAVEATS_END = '</section>\n\n</div><!-- /main-reco'
CAVEATS_NEW = """
  <h2>Bench shortcomings</h2>
  <p class="lead">Points the reader should know before drawing conclusions. These are limitations of the dataset, not of the scanners.</p>
  <div class="callout">
    <strong>OpenVAS ran successfully on juice-shop.</strong> 56 findings (2 high, 4 medium, 6 low, 44 log, severity 8.1). Wall time 39 min after NVT sync (~20 min). DVWA and WebGoat not run — the aggregate time would be ~2 h for OpenVAS alone.
  </div>
  <div class="callout warn">
    <strong>9 scanners with a broken Docker wrapper:</strong> cdxgen, Clair, dependency-check, govulncheck, guarddog, jaeles, kube-linter, pip-audit, SecretScanner. All exit with code 0 but write no artifacts. Causes vary: the image changed its ENTRYPOINT, the scanner finds no input in its domain, a UID/GID failure, missing AVX2. Status recorded as <code>ok</code> in metrics.json.
  </div>
  <div class="callout warn">
    <strong>WhatWeb returned 0 fingerprints on all targets.</strong> Likely a misconfig (Host header) or the collector's sampling window below the run duration (~10 s).
  </div>
  <div class="callout warn">
    <strong>Whispers has a high default sensitivity:</strong> 6,034 findings across the 3 targets vs. 116 from TruffleHog (verified). Without rule tuning it becomes noise.
  </div>
  <div class="callout warn">
    <strong>Schema heterogeneity:</strong> severities as <code>HIGH</code> (Trivy), <code>High</code> (Grype), <code>high</code> (Nuclei), <code>"Medium (Medium)"</code> (ZAP), <code>Critical/Alarm/Log</code> (OpenVAS). Cross-tool aggregation requires explicit normalization.
  </div>
"""


# ─── Pipeline ──────────────────────────────────────────────────────────────

def is_integrated(content: str) -> bool:
    """Have new-scanner UI fragments already been merged?"""
    return "tabbtn-arachni" in content and "tab-arachni" in content


def run_legacy_injectors() -> None:
    """Re-run the existing legacy scripts (each one targets a specific concern)."""
    for name in ("integrate_new_scanners.py", "patch_existing_html.py",
                 "extract_detail.py", "inject_renderers.py"):
        p = SCRIPTS / name
        r = subprocess.run([sys.executable, str(p)], capture_output=True, text=True)
        if r.returncode != 0:
            sys.stderr.write(f"[{name}] FAILED:\n{r.stderr}\n")
            sys.exit(1)


sys.path.insert(0, str(SCRIPTS))
from scanner_specs import SCANNERS, by_mode  # noqa: E402

def _gen_stacks() -> tuple[str, str]:
    """Build STACKS literal from the registry. The 'min' subsets stay manual."""
    s = lambda lst: "[" + ",".join(f"'{x}'" for x in sorted(lst)) + "]"
    static_full = [n for n in by_mode("static") if SCANNERS[n].stack != "exclude"]
    dyn_full = [n for n in by_mode("dynamic") if SCANNERS[n].stack != "exclude"]
    new = (f"const STACKS = {{\n"
           f"  static_full: {s(static_full)},\n"
           f"  static_min:  ['trivy','trufflehog','dockle','osv'],\n"
           f"  dyn_full:    {s(dyn_full)},\n"
           f"  dyn_light:   ['nmap','zap','httpx'],\n"
           f"}};")
    old = ("const STACKS = {\n"
           "  static_full: ['syft','grype','trivy','trufflehog','dockle'],\n"
           "  static_min:  ['trivy','trufflehog','dockle'],\n"
           "  dyn_full:    ['nmap','nuclei','zap'],\n"
           "  dyn_light:   ['nmap','zap'],\n"
           "};")
    return old, new

_STACKS_OLD, _STACKS_NEW = _gen_stacks()


def _autosync_openvas_counts(content: str) -> tuple[str, bool]:
    """Pull openvas badge/text counts from DETAIL extractor output instead of
    hard-coding. Single source of truth: extract_detail.py → DETAIL.openvas.
    """
    detail_path = ROOT / "reports" / "scans-output" / "_detail.json"
    if not detail_path.exists():
        return content, False
    try:
        d = json.loads(detail_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return content, False
    findings = d.get("openvas", {}).get("findings", [])
    if not findings:
        return content, False
    total = len(findings)
    sev = {"high": 0, "medium": 0, "low": 0, "log": 0, "critical": 0}
    for f in findings:
        t = (f.get("threat") or "Log").lower()
        if t in sev:
            sev[t] += 1
        else:
            sev["log"] += 1
    sev_str = (f"high: {sev['high']}, medium: {sev['medium']}, "
               f"low: {sev['low']}, log: {sev['log']}")
    changed = False
    for old_n in (5, 14, 33, 34, 56, 70):
        for old, new in [
            (f'>openvas<span class="badge">{old_n}</span>',
             f'>openvas<span class="badge">{total}</span>'),
            (f'<span class="v">{old_n}</span><span class="l">findings</span>',
             f'<span class="v">{total}</span><span class="l">findings</span>'),
            (f"Found {old_n} findings on juice-shop",
             f"Found {total} findings on juice-shop"),
            (f"now run: {old_n} findings on juice-shop",
             f"now run: {total} findings on juice-shop"),
        ]:
            if old in content and old != new:
                content = content.replace(old, new, 1)
                changed = True
    # Update breakdown line in panel description (regex-safe with bounded prefix)
    import re as _re
    breakdown_pat = _re.compile(
        r"<dt>Total findings</dt><dd><b>\d+</b> \(juice-shop only[^<]*\) "
        r"Severities: <b>[^<]+</b>\. Severity score: 8\.1\.</dd>"
    )
    new_block = (f"<dt>Total findings</dt><dd><b>{total}</b> "
                 f"(juice-shop only — dvwa/webgoat not run due to time cost). "
                 f"Severities: <b>{sev_str}</b>. Severity score: 8.1.</dd>")
    new_content, n = breakdown_pat.subn(new_block, content, count=1)
    if n:
        content = new_content
        changed = True
    return content, changed


def apply_text_blocks(content: str) -> str:
    """Apply lead/badge/openvas-card/recos/caveats updates with slice-based
    replaces. Each replace is independent — if anchor missing, no-op."""
    edits = [
        ("lead+badge",      _normalize_lead_and_badge),
        ("stacks",          lambda c: replace_text(c, _STACKS_OLD, _STACKS_NEW)),
        ("recos",           lambda c: replace_between(c, RECOS_START, RECOS_END, RECOS_NEW)),
        ("caveats",         lambda c: replace_between(c, CAVEATS_START, CAVEATS_END, CAVEATS_NEW)),
        ("openvas-coverage-row", lambda c: replace_text(
            c,
            '<tr><td><strong>openvas</strong> <span class="tag warn">not run</span></td>',
            '<tr><td><strong>openvas</strong></td>')),
        ("openvas-calc-toggle", _ensure_openvas_calc),
        ("openvas-counts",      _autosync_openvas_counts),
    ]
    for label, fn in edits:
        content, changed = fn(content)
        if changed:
            print(f"  ✓ {label}")
    return content


_OPENVAS_TOGGLE = ('        <label class="calc-toggle" data-scanner="openvas">\n'
                   '          <input type="checkbox">\n'
                   '          <span>openvas</span>\n'
                   '          <span class="tag dynamic">d</span>\n'
                   '        </label>\n')


def _ensure_openvas_calc(content: str) -> tuple[str, bool]:
    """Insert openvas calc-toggle right after zap's, idempotently."""
    if 'data-scanner="openvas"' in content:
        return content, False
    anchor = ('        <label class="calc-toggle" data-scanner="zap">\n'
              '          <input type="checkbox">\n'
              '          <span>zap</span>\n'
              '          <span class="tag dynamic">d</span>\n'
              '        </label>')
    return replace_text(content, anchor, anchor + "\n" + _OPENVAS_TOGGLE.rstrip())


def replace_openvas_card(content: str) -> tuple[str, bool]:
    """Whole-card replacement (the helper above is awkward — do it explicitly)."""
    start_idx = content.find(OPENVAS_CARD_OLD_START)
    if start_idx < 0:
        return content, False
    # End is the next </article> after this <article>
    end_idx = content.find(OPENVAS_CARD_OLD_END, start_idx + len(OPENVAS_CARD_OLD_START))
    if end_idx < 0:
        return content, False
    end_idx += len(OPENVAS_CARD_OLD_END)
    return content[:start_idx] + OPENVAS_CARD_NEW + content[end_idx:], True


def refresh_data_dict(content: str, varname: str, value: dict) -> str:
    """Idempotent literal replace bounded by `const NAME = ` and matching `};\\n`."""
    needle = f"const {varname} = "
    i = content.find(needle)
    if i < 0:
        return content
    # Walk to find balanced close — naive brace counter
    j = content.find("{", i)
    depth = 0
    in_str = False
    escape = False
    k = j
    while k < len(content):
        ch = content[k]
        if escape:
            escape = False
        elif ch == "\\":
            escape = True
        elif ch == '"':
            in_str = not in_str
        elif not in_str:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
        k += 1
    if depth != 0 or content[k:k+3] != "};\n":
        # Suffix mismatch; leave alone
        return content
    return (content[:i] + needle
            + json.dumps(value, ensure_ascii=False)
            + ";\n" + content[k+3:])


def collect():
    """Re-use extractors via the scripts module."""
    sys.path.insert(0, str(SCRIPTS))
    from extract_detail import EXTRACTORS, TARGETS as EX_TARGETS  # type: ignore
    detail = {s: {"meta": {"scanner": s, "targets": EX_TARGETS},
                  "findings": fn()} for s, fn in EXTRACTORS.items()}

    # DATA: read existing DATA, then refresh entries for scanners that have
    # metrics. The schema must match what the JS expects — we mirror the
    # integrate_new_scanners output.
    HOSTS = ["node1", "node2"]
    SCANS_OUT = ROOT / "reports" / "scans-output"
    metrics_data = {}
    # Get the existing DATA from the HTML to preserve the original-14
    content = HTML.read_text(encoding="utf-8")
    m = re.search(r"const DATA = (\{.*?\});\n", content, flags=re.S)
    if m:
        try:
            metrics_data = json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    # Refresh by overwriting entries for which we have current metrics
    for tgt in EX_TARGETS:
        for host in HOSTS:
            mf = SCANS_OUT / host / tgt / f"{tgt}-metrics.json"
            if not mf.exists():
                continue
            try:
                entries = json.loads(mf.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            for e in entries:
                name = e.get("scanner")
                if not name or name not in EXTRACTORS:
                    continue
                if name == "openvas" and host == "node2":
                    continue
                d = SCANS_OUT / host / tgt / name
                findings_count = (len(EXTRACTORS[name]())
                                  if False else  # extractors are aggregate, not per-target
                                  sum(1 for f in (detail.get(name, {}).get("findings") or [])
                                      if f.get("target") == tgt))
                rec = metrics_data.setdefault(name, {
                    "name": name, "mode": "static", "type": e.get("scanner", name),
                    "wall_avg": 0, "cpu_max": 0, "mem_max": 0,
                    "wall_per_target": {}, "findings": 0,
                    "by_target_findings": {}, "covers": [], "ran": True,
                })
                rec["wall_per_target"][tgt] = round(e.get("wall_seconds", 0), 2)
                rec["by_target_findings"][tgt] = findings_count
                rec["cpu_max"] = max(rec.get("cpu_max", 0), e.get("peak_cpu_percent", 0))
                rec["mem_max"] = max(rec.get("mem_max", 0), e.get("peak_mem_mb", 0))
                rec["ran"] = True
    for rec in metrics_data.values():
        if rec.get("wall_per_target"):
            rec["wall_avg"] = sum(rec["wall_per_target"].values()) / len(rec["wall_per_target"])
        rec["findings"] = sum(rec.get("by_target_findings", {}).values())
    return metrics_data, detail


def validate(content: str) -> list[str]:
    errs = []
    n_tabs = content.count('id="tabbtn-')
    n_panels = content.count('class="tab-panel"')
    if n_tabs < 30:
        errs.append(f"too few tab buttons: {n_tabs}")
    if n_panels < 15:
        errs.append(f"too few panels: {n_panels}")
    if "const DATA = {" not in content:
        errs.append("DATA literal missing")
    if "const DETAIL = {" not in content:
        errs.append("DETAIL literal missing")
    return errs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--reset", action="store_true",
                    help="Restore from .bak before rebuilding")
    args = ap.parse_args()

    if args.reset:
        if BAK.exists():
            shutil.copy(BAK, HTML)
            print(f"restored from {BAK}")
        else:
            print(f"no backup at {BAK}", file=sys.stderr)
            sys.exit(1)

    if args.check:
        errs = validate(HTML.read_text(encoding="utf-8"))
        if errs:
            for e in errs:
                print(f"  - {e}")
            sys.exit(2)
        print("OK")
        return

    content = HTML.read_text(encoding="utf-8")
    if not is_integrated(content):
        print("First run — running legacy injector chain")
        run_legacy_injectors()
        content = HTML.read_text(encoding="utf-8")

    print("Applying text-block updates")
    content = apply_text_blocks(content)
    content, ok = replace_openvas_card(content)
    if ok:
        print("  ✓ openvas-card")

    print("Refreshing DATA + DETAIL from scan-output")
    data, detail = collect()
    # Merge new detail into existing
    m = re.search(r"const DETAIL = (\{.*?\});\n", content, flags=re.S)
    existing_detail = json.loads(m.group(1)) if m else {}
    existing_detail.update(detail)
    content = refresh_data_dict(content, "DATA", data)
    content = refresh_data_dict(content, "DETAIL", existing_detail)

    HTML.write_text(content, encoding="utf-8")
    errs = validate(content)
    if errs:
        print("WARNING — validation issues:")
        for e in errs:
            print(f"  - {e}")
        sys.exit(2)
    print(f"OK — wrote {HTML.relative_to(ROOT)} ({len(content):,} chars)")


if __name__ == "__main__":
    main()
