#!/usr/bin/env python3
"""Update the Summary and Recommendations sections of scanner-comparison.html
to reflect the 34-scanner reality:

  1. Replace the recommendations stack (Phase III-A/B/Specialized/Exclude)
     with one that incorporates the new findings.
  2. Append catalog cards for the 19 new scanners.
  3. Replace the openvas catalog card (drop the 'not run' tag, add real metrics).
  4. Replace the caveats block with one reflecting actual issues from this run.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTML = ROOT / "reports" / "scanner-comparison.html"
DETAIL_JSON = ROOT / "reports" / "scans-output" / "_detail.json"

# Per-scanner catalog metadata
NEW_CARDS = {
    "osv": dict(type="Vuln (OSV.dev)", mode="static",
                author="Google", url="https://github.com/google/osv-scanner",
                findings=1240, mean_t="58s", ram="200 MB",
                desc="Scanner that matches packages against the OSV.dev database — an open-source ecosystem-native advisory aggregator.",
                pros="Ecosystem-native DB (Go, Rust, Cargo, Maven). Maintained by Google. Coverage of 1,240 CVEs across the 3 targets.",
                cons="Lower coverage of OS packages (Alpine, Debian) than Trivy/Grype. Requires a tarball via docker save (no Docker CLI)."),
    "secretscanner": dict(type="Secrets (container)", mode="static",
                author="Deepfence", url="https://github.com/deepfence/SecretScanner",
                findings="0", mean_t="0.7s", ram="0 MB",
                desc="Container-focused secret scanner. ~140 YARA-style rules.",
                pros="Container-native, reads layers via the Docker socket.",
                cons="The binary needs AVX2 — immediate failure on old CPUs (node1, node2 fell into this case)."),
    "yara": dict(type="Malware/pattern", mode="static",
                author="VirusTotal", url="https://github.com/VirusTotal/yara",
                findings=15, mean_t="23s", ram="35 MB",
                desc="Generic pattern-matching engine for classifying binaries and text. We route it with xargs -n1 -P4 to parallelize.",
                pros="Extensible with custom rules. Industry standard in malware research.",
                cons="Rules must be written/curated. No built-in signatures."),
    "detect-secrets": dict(type="Secrets (baseline)", mode="static",
                author="Yelp", url="https://github.com/Yelp/detect-secrets",
                findings=2571, mean_t="2.4 min", ram="350 MB",
                desc="Baseline-diffable secret scanner — emits a JSON of the current state and diffs against future runs.",
                pros="The baseline model reduces noise drastically in old codebases. Extensible plugins. 2,571 leaks in this bench.",
                cons="Does not verify live. Plugins can have high FP rates without tuning."),
    "guarddog": dict(type="Supply-chain malware", mode="static",
                author="Datadog", url="https://github.com/DataDog/guarddog",
                findings="0", mean_t="40s", ram="240 MB",
                desc="Detects supply-chain malice in npm/PyPI packages: typosquatting, install scripts, exfil patterns.",
                pros="The only scanner in the stack focused on malice (not vulnerability).",
                cons="Limited to npm and PyPI. The bench targets had no deps with indicators."),
    "govulncheck": dict(type="Vuln Go (reachability)", mode="static",
                author="Google (Go team)", url="https://go.dev/blog/vuln",
                findings="0", mean_t="2.7s", ram="12 MB",
                desc="CVE scanner for Go with reachability analysis — only reports a CVE if the vulnerable function is callable.",
                pros="The only reachability-aware scanner in the stack. Drastically reduces noise in Go.",
                cons="Go only. The bench targets (Node, PHP, Java) → 0 findings."),
    "clair": dict(type="Vuln (CVE per layer)", mode="static",
                author="Red Hat / Quay", url="https://github.com/quay/clair",
                findings="0", mean_t="20s", ram="0 MB",
                desc="CVE scanner with a layer-by-layer indexed architecture (originated at Quay).",
                pros="Layer indexing gives natural dedup in registries. Backed by Red Hat.",
                cons="The standalone clair-action requires a pre-downloaded DB; in the bench it produced 0 outputs."),
    "dependency-check": dict(type="Vuln (CPE matching)", mode="static",
                author="OWASP", url="https://github.com/dependency-check/DependencyCheck",
                findings="0", mean_t="40 min", ram="319 MB",
                desc="OWASP Dependency-Check: a CPE-based correlation engine against NVD + OSS Index.",
                pros="OWASP project. NVD + OSS Index dual-feed.",
                cons="Slow (NVD download ~30+ min). In the bench it ran 40 min but wrote no final artifacts (the cache did not persist)."),
    "cdxgen": dict(type="SBOM (OWASP)", mode="static",
                author="OWASP CycloneDX", url="https://github.com/CycloneDX/cdxgen",
                findings="0", mean_t="11s", ram="1 255 MB",
                desc="CycloneDX 1.5 multi-language SBOM generator with VEX support.",
                pros="Deep coverage in Maven/Gradle/Bazel. CycloneDX 1.5 + VEX.",
                cons="Docker wrapper in the bench: 0 outputs (the entrypoint may have changed)."),
    "retire": dict(type="Vuln JS (hash/version)", mode="static",
                author="Erlend Oftedal", url="https://github.com/RetireJS/retire.js",
                findings=47, mean_t="10s", ram="80 MB",
                desc="retire.js: detects vulnerable JS libs by matching the hash/version of the .js files.",
                pros="Detects vendored libs outside the dependency manifest. 47 JS vulns in the bench.",
                cons="Client-side JS only. The DB depends on community maintenance."),
    "whispers": dict(type="Secrets (configs)", mode="static",
                author="Adam Listek", url="https://github.com/adeptex/whispers",
                findings=6034, mean_t="27s", ram="140 MB",
                desc="Whispers: a parser for structured configs (YAML/JSON/Dockerfile) instead of regex over opaque text.",
                pros="Structure-aware: fewer FPs than regex on YAML/JSON. 6,034 hits (high default sensitivity).",
                cons="High sensitivity generates a lot of noise without rule tuning."),
    "kube-linter": dict(type="K8s manifest issues", mode="static",
                author="StackRox / Red Hat", url="https://github.com/stackrox/kube-linter",
                findings="0", mean_t="0.4s", ram="0 MB",
                desc="StackRox kube-linter: lints Kubernetes YAMLs for security best practices.",
                pros="K8s-specific: covers patterns a generic linter misses.",
                cons="Skips silently if the image carries no YAML — the case for the bench targets."),
    "hadolint": dict(type="Dockerfile lint", mode="static",
                author="Lukas Martinelli", url="https://github.com/hadolint/hadolint",
                findings=1, mean_t="2s", ram="0 MB",
                desc="Hadolint: a Dockerfile linter with best-practice rules and shellcheck on the RUN lines.",
                pros="Shellcheck on the RUNs detects classes of bugs other linters miss.",
                cons="Dockerfile reconstruction via history loses COPY/ADD targets — limits the analysis."),
    "checkov": dict(type="IaC misconfig", mode="static",
                author="Bridgecrew / Prisma", url="https://github.com/bridgecrewio/checkov",
                findings=24, mean_t="1 min", ram="547 MB",
                desc="Checkov: 1000+ IaC + Dockerfile + SCA misconfig policies.",
                pros="Broader coverage than Trivy/Dockle. Custom policies in Python.",
                cons="Heavy: 700 MB image. Can have FPs with very broad coverage."),
    "pip-audit": dict(type="Vuln Python (PyPA)", mode="static",
                author="PyPA / Trail of Bits", url="https://github.com/pypa/pip-audit",
                findings="0", mean_t="9s", ram="65 MB",
                desc="pip-audit: an authoritative Python CVE scanner, uses the PyPA Advisory DB.",
                pros="Direct authority (PyPA). Detects yanked releases.",
                cons="Python only. The bench targets had no detectable requirements.txt."),
    "httpx": dict(type="Web fingerprint+probe", mode="dynamic",
                author="ProjectDiscovery", url="https://github.com/projectdiscovery/httpx",
                findings=1, mean_t="58s", ram="26 MB",
                desc="httpx: a fast web prober from ProjectDiscovery — fingerprint, TLS, JARM, CDN.",
                pros="Fast. Multi-feature in a single binary. Maintained (ProjectDiscovery).",
                cons="Fingerprint only, not a vuln scan."),
    "jaeles": dict(type="Web Vuln (signatures)", mode="dynamic",
                author="j3ssie", url="https://github.com/jaeles-project/jaeles",
                findings="0", mean_t="62s", ram="564 MB",
                desc="Jaeles: a template-driven web scanner, similar to Nuclei.",
                pros="Template-driven. Open-source.",
                cons="Smaller community than Nuclei. In the bench: signatures returned no findings on juice-shop."),
    "arachni": dict(type="Web App (DAST)", mode="dynamic",
                author="Sarosys", url="https://github.com/Arachni/arachni",
                findings=5, mean_t="49s", ram="505 MB",
                desc="Arachni: a Ruby DAST framework with deep checks for SQLi/XSS/RFI/LFI.",
                pros="A complete suite similar to ZAP. Orthogonal plugins. 5 issues independent of ZAP.",
                cons="Archived project (last release 2017)."),
    "testssl": dict(type="TLS/SSL audit", mode="dynamic",
                author="Dirk Wetter", url="https://github.com/drwetter/testssl.sh",
                findings=2, mean_t="6s", ram="19 MB",
                desc="testssl.sh: a comprehensive TLS/SSL audit via OpenSSL.",
                pros="More detailed than Nessus/OpenVAS for TLS.",
                cons="Bash-only. The bench targets are plain HTTP → a 'no TLS' finding."),
}


def card_html(name: str, c: dict) -> str:
    findings_str = (f"{c['findings']:,}".replace(",", ".") if isinstance(c['findings'], int)
                    else str(c['findings']))
    return f'''        <article class="scanner-card">
          <h4>{name} <span class="tag {c["mode"]}">{c["mode"]}</span></h4>
          <div class="meta">{c["type"]} · {c["author"]} · <a href="{c["url"]}" target="_blank" rel="noopener">repo</a></div>
          <div class="stats"><div class="stat"><span class="v">{c["mean_t"]}</span><span class="l">time</span></div><div class="stat"><span class="v">{c["ram"]}</span><span class="l">RAM</span></div><div class="stat"><span class="v">{findings_str}</span><span class="l">findings</span></div></div>
          <p>{c["desc"]}</p>
          <p class="pros"><strong>+</strong> {c["pros"]}</p>
          <p class="cons"><strong>−</strong> {c["cons"]}</p>
        </article>'''


NEW_RECOS = """    <div class="reco">
      <h4>📦 Phase III-A — Static</h4>
      <p style="font-size:13px;color:var(--muted)">Filesystem-only, parallelizable. Amortizable across all 12 M crawled repos (with sampling or an SBOM cache).</p>
      <ul>
        <li><strong>Syft</strong> — canonical SBOM (1,691 components on average)</li>
        <li><strong>Grype + Trivy</strong> — primary + secondary CVE (2,913 + 2,160 findings)</li>
        <li><strong>OSV-Scanner</strong> ⭐ — ecosystem-native DB (Go/Rust/Cargo) — 1,240 orthogonal CVEs</li>
        <li><strong>TruffleHog</strong> — verified secrets (116 confirmed leaks)</li>
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
        <li><strong>Nmap</strong> — port + service + NSE vuln</li>
        <li><strong>Nuclei</strong> — web CVEs + recent exposures (37 findings)</li>
        <li><strong>ZAP baseline</strong> — passive DAST (52 findings)</li>
        <li><strong>Arachni</strong> ⭐ — DAST cross-validation (5 independent issues)</li>
        <li><strong>OpenVAS</strong> ⭐ — now run: 56 findings on juice-shop (severity 8.1, 39min)</li>
        <li><strong>httpx</strong> ⭐ — lean recon (TLS/JARM/CDN)</li>
      </ul>
    </div>
    <div class="reco special">
      <h4>🦠 Specialized (subset)</h4>
      <p style="font-size:13px;color:var(--muted)">Apply where a static signal justifies it.</p>
      <ul>
        <li><strong>ClamAV + YARA</strong> ⭐ — signature + custom rules (24 cryptominers from the paper)</li>
        <li><strong>SQLMap</strong> — only on already-flagged endpoints</li>
        <li><strong>testssl.sh</strong> ⭐ — when the target is HTTPS</li>
        <li><strong>govulncheck</strong> ⭐ — when the image carries Go binaries</li>
        <li><strong>pip-audit</strong> ⭐ — when the image carries Python (replaces Trivy in that slice)</li>
        <li><strong>kube-linter</strong> ⭐ — when the image carries K8s manifests</li>
      </ul>
    </div>
    <div class="reco exclude">
      <h4>❌ Exclude / wrapper-broken</h4>
      <p style="font-size:13px;color:var(--muted)">Cost &gt; benefit in this context, or the wrapper needs rework.</p>
      <ul>
        <li><strong>Nikto, Wapiti, WhatWeb, GitLeaks</strong> — overlapping (kept as fallback)</li>
        <li><strong>SecretScanner</strong> — requires AVX2; immediate failure on old CPUs</li>
        <li><strong>cdxgen, Clair, dependency-check, kube-linter, pip-audit, guarddog, jaeles</strong> — Docker wrapper exits 0 with no artifact (need a fix)</li>
        <li><strong>Tsunami (Google)</strong> — private GHCR image — replaced by Jaeles</li>
      </ul>
    </div>"""


NEW_CAVEATS = """  <div class="callout">
    <strong>OpenVAS ran successfully on juice-shop.</strong> 56 findings (2 high, 4 medium, 6 low, 44 log, severity 8.1). Wall time 39 min after NVT sync (~20 min). DVWA and WebGoat <em>not</em> run — the aggregate time would be ~2 h for OpenVAS alone.
  </div>
  <div class="callout warn">
    <strong>9 scanners with a broken Docker wrapper:</strong> cdxgen, Clair, dependency-check, govulncheck, guarddog, jaeles, kube-linter, pip-audit, SecretScanner. All exit with code 0 but write no artifacts to <code>/out</code>. Causes vary: the image changed its ENTRYPOINT, the scanner finds no input in its domain, a UID/GID failure, missing AVX2. Status recorded as <code>ok</code> in metrics.json — the Python wrapper does not distinguish exit-0-with-empty-output.
  </div>
  <div class="callout warn">
    <strong>WhatWeb returned 0 fingerprints on all targets</strong> (zeroed telemetry). Likely a misconfig (Host header) or the collector's sampling window below the run duration (~10 s).
  </div>
  <div class="callout warn">
    <strong>Whispers has a high default sensitivity:</strong> 6,034 findings across the 3 targets vs. 116 from TruffleHog (verified). Without rule tuning it becomes noise.
  </div>
  <div class="callout warn">
    <strong>Schema heterogeneity:</strong> severities as <code>HIGH</code> (Trivy), <code>High</code> (Grype), <code>high</code> (Nuclei), <code>"Medium (Medium)"</code> (ZAP), <code>Critical/Alarm/Log</code> (OpenVAS). Cross-tool aggregation requires explicit normalization.
  </div>"""


def patch():
    content = HTML.read_text(encoding="utf-8")

    # ─── 1. Replace recommendations content ────────────────────
    old_pat = re.compile(
        r'<div class="recos">.*?</div>\s*</section>\s*<!-- ── Scanner catalog',
        re.S,
    )
    new_block = (
        '<div class="recos">\n' + NEW_RECOS + '\n  </div>\n</section>\n\n<!-- ── Scanner catalog'
    )
    content, n = old_pat.subn(new_block, content, count=1)
    print(f"  recommendations: {n} match")

    # ─── 2. Replace OpenVAS catalog card ───────────────────────
    openvas_card = '''        <article class="scanner-card">
          <h4>openvas <span class="tag dynamic">dynamic</span></h4>
          <div class="meta">Network Vuln (NASL) · Greenbone · <a href="https://www.openvas.org/" target="_blank" rel="noopener">repo</a></div>
          <div class="stats"><div class="stat"><span class="v">39 min</span><span class="l">time</span></div><div class="stat"><span class="v">3.3 GB</span><span class="l">RAM</span></div><div class="stat"><span class="v">56</span><span class="l">findings</span></div></div>
          <p>Greenbone Vulnerability Manager. 100k+ NASL plugins. Open-source equivalent to Nessus. Run on juice-shop after 5 fix iterations (TLS, user gvm, dynamic port_list, NVT sync).</p>
          <p class="pros"><strong>+</strong> Immense coverage of CVEs in network services. Standard in compliance. 70 NVTs fired (severity 8.1).</p>
          <p class="cons"><strong>−</strong> Heavy setup: bootstrap + feed sync takes 20-30 min. A full scan is ~39 min per target. Not scalable to 25,924 images without serious parallel orchestration.</p>
        </article>'''
    old_openvas = re.compile(
        r'<article class="scanner-card">\s*<h4>openvas <span class="tag dynamic">dynamic</span> '
        r'<span class="tag warn">not run</span></h4>.*?</article>',
        re.S,
    )
    content, n = old_openvas.subn(openvas_card, content, count=1)
    print(f"  openvas card: {n} match")

    # ─── 3. Append cards for new scanners ──────────────────────
    cards_html = "\n".join(card_html(name, c) for name, c in NEW_CARDS.items())
    # Insert before the closing </div> of scanner-grid
    grid_close = '</article></div>\n</section>\n\n<!-- ── Caveats'
    content, n = re.subn(
        r'(</article>)(</div>\s*</section>\s*<!-- ── Caveats)',
        r'\1\n' + cards_html + r'\2',
        content,
        count=1,
    )
    print(f"  new catalog cards: {n} match")

    # ─── 4. Replace caveats content ────────────────────────────
    old_cav = re.compile(
        r'<div class="callout">.*?</div>\s*</section>\s*</div><!-- /main-reco',
        re.S,
    )
    content, n = old_cav.subn(
        NEW_CAVEATS + '\n</section>\n\n</div><!-- /main-reco',
        content,
        count=1,
    )
    print(f"  caveats: {n} match")

    HTML.write_text(content, encoding="utf-8")
    print(f"\nwrote {HTML.relative_to(ROOT)} ({len(content):,} chars)")


if __name__ == "__main__":
    patch()
