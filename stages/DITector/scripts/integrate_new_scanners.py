#!/usr/bin/env python3
"""Integrate phase-2 + phase-3 scanner results into the original
reports/scanner-comparison.html. Modifies that file in-place — the
companion file scanner-comparison-new.html is removed when done.

Steps (surgical, no rewrite):
1. Load metrics + findings from reports/scans-output/{node2,node1}/<target>/<scanner>/.
2. Build a DATA-dict fragment matching the existing schema and merge it into
   the JS DATA literal on line 1111.
3. Append a calc-toggle for each new scanner in the toggles fieldset.
4. Append a tab button for each new scanner in the per-scanner tablist.
5. Append a tab-panel block (header + scanner-info section) for each new
   scanner, matching the openvas placeholder layout.
6. Insert coverage-matrix rows in the matrix tbody.
7. Update the "Por scanner" badge count.
"""
from __future__ import annotations

import html
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTML_PATH = ROOT / "reports" / "scanner-comparison.html"
NEW_HTML = ROOT / "reports" / "scanner-comparison-new.html"
SCANS_OUT = ROOT / "reports" / "scans-output"

HOSTS = ["node1", "node2"]  # node1 wins for shared scanners (more recent)
TARGETS = ["webgoat", "dvwa", "juice-shop"]
ORIGINAL = {"syft", "trivy", "grype", "dockle", "trufflehog", "gitleaks",
            "clamav", "whatweb", "nmap", "nikto", "nuclei", "wapiti", "zap",
            "sqlmap", "openvas"}

# Per-scanner profile (matches the existing scanner-info <dl> shape).
INFO = {
    "osv": dict(type="Vuln (OSV.dev)", mode="static", since="2022", author="Google",
                license="Apache-2.0",
                covers=["cve", "sbom"],
                what="Scanner that matches packages against the OSV.dev database — an open-source ecosystem-native advisory aggregator.",
                how="Reads SBOMs or images via tarball; queries the osv.dev REST API and Maven Central, npm, PyPI, RubyGems, crates.io to map version→advisory ID. JSON/SARIF output.",
                when="When you need to cover Go modules, Rust crates, Cargo — where NVD tends to lag. Cross-validation with Trivy/Grype.",
                pros="Ecosystem-native DB (Go, Rust, Cargo, Maven). Maintained by Google. Weekly updates.",
                cons="Lower coverage of OS packages (Alpine, Debian) than Trivy/Grype.",
                alts="Trivy (broader), Grype (CVE-only), Snyk (commercial)."),
    "secretscanner": dict(type="Secrets (container)", mode="static", since="2020",
                author="Deepfence", license="Apache-2.0", covers=["secrets"],
                what="Container-focused secret scanner. ~140 YARA-style rules.",
                how="Mounts the Docker socket, indexes layers, and runs YARA rules against the extracted files. JSON output.",
                when="When the image carries tokens/keys in its layers (env files, JWTs, AWS keys). Complements TruffleHog for container-specific patterns.",
                pros="Container-native, no need to export the FS. The YARA engine allows custom rules.",
                cons="The binary needs AVX2 — fails on old CPUs. No active verification (regex-only).",
                alts="TruffleHog (with API verification), GitLeaks, Whispers (structured configs)."),
    "yara": dict(type="Malware/pattern", mode="static", since="2007", author="VirusTotal",
                license="BSD-3", covers=["malware"],
                what="Generic pattern-matching engine for classifying binaries and text.",
                how="Compiles rules (.yar) into bytecode and runs them against files. Supports strings, bytes, regex, hex. We route it via xargs -n1 -P4 to parallelize.",
                when="Detecting cryptominers, reverse shells, embedded private keys. Custom rules for specific campaigns.",
                pros="Extensible with custom rules. Industry standard in malware research. Fast.",
                cons="Rules must be written/curated. No built-in signatures.",
                alts="ClamAV (signature-only), Capa (FLARE, behavior-based)."),
    "detect-secrets": dict(type="Secrets (baseline)", mode="static", since="2018",
                author="Yelp", license="Apache-2.0", covers=["secrets"],
                what="Baseline-diffable secret scanner — emits a JSON of the current state and diffs against future runs.",
                how="Plugin-based (AWS, JWT, Slack, base64-high-entropy). pip install detect-secrets, scan --all-files. Each finding has a hash + offset.",
                when="Long-lived repos with known historical secrets: it records the baseline and flags only new ones.",
                pros="The baseline model reduces noise drastically in old codebases. Extensible plugins.",
                cons="Does not verify live (unlike TruffleHog). Plugins can have high FP rates without tuning.",
                alts="TruffleHog (verifies via API), GitLeaks, Whispers."),
    "guarddog": dict(type="Supply-chain malware", mode="static", since="2022",
                author="Datadog", license="Apache-2.0", covers=["supplychain"],
                what="Detects supply-chain malice in npm/PyPI packages: typosquatting, install scripts, exfil patterns.",
                how="Does AST analysis of package source code with Semgrep + heuristics. For each package: download → scan → score.",
                when="Auditing the dependencies of an image before production. Covers a class of attacks NVD/GHSA do not (CVEs vs. malice).",
                pros="The only scanner in the stack focused on malice (not vulnerability). Maintained by Datadog.",
                cons="Limited to npm and PyPI. Slow (download + AST per package).",
                alts="Phylum (commercial), Snyk Advisor, Sonatype Nexus."),
    "govulncheck": dict(type="Vuln Go (reachability)", mode="static", since="2022",
                author="Google (Go team)", license="BSD-3", covers=["cve"],
                what="CVE scanner for Go with reachability analysis — only reports a CVE if the vulnerable function is callable.",
                how="Reads the binary's BuildInfo (Go 1.18+) or source modules; builds a call graph; matches against the vuln.go.dev DB. Reports only reachable paths.",
                when="Go-heavy images. Reduces false positives by 30-70% vs. Trivy/Grype in CVE detection.",
                pros="The only reachability-aware scanner in the stack. Drastically reduces noise in Go.",
                cons="Go only. Binaries without BuildInfo (Go ≤1.17) are skipped.",
                alts="Trivy (no reachability), Grype (idem). For other langs: pip-audit (Python), npm audit (Node)."),
    "clair": dict(type="Vuln (CVE per layer)", mode="static", since="2015",
                author="CoreOS / Red Hat", license="Apache-2.0", covers=["cve"],
                what="CVE scanner with a layer-by-layer indexed architecture (originated at Quay).",
                how="Each image layer is indexed separately; CVEs matched per layer. clair-action is a single-binary wrapper that avoids the full server stack.",
                when="A third opinion when Trivy and Grype diverge. The per-layer dedup model is useful in large registries.",
                pros="Layer indexing gives natural dedup in registries. Backed by Red Hat.",
                cons="The full server setup is heavy (Postgres + matchers); the standalone action is lighter but with less coverage.",
                alts="Trivy, Grype, Anchore Engine."),
    "dependency-check": dict(type="Vuln (CPE matching)", mode="static", since="2012",
                author="OWASP (Jeremy Long)", license="Apache-2.0", covers=["cve"],
                what="OWASP Dependency-Check: a CPE-based correlation engine against NVD.",
                how="Identifies Maven/Gradle/npm/Nuget/Python/etc components; generates a CPE (Common Platform Enumeration); matches against NVD + OSS Index. Heuristic confidence score.",
                when="Strong in Java (Maven coords → well-defined CPE). Standard in OWASP-focused pipelines.",
                pros="OWASP project. NVD + OSS Index dual-feed. SARIF/HTML/JSON/JUnit/CSV output.",
                cons="Slow on the 1st run (NVD download ~30+ min). False positives on ambiguous coords. CPE matching is heuristic.",
                alts="Snyk (commercial), Trivy, Grype."),
    "cdxgen": dict(type="SBOM (OWASP)", mode="static", since="2021",
                author="OWASP (CycloneDX)", license="Apache-2.0", covers=["sbom"],
                what="CycloneDX 1.5 multi-language SBOM generator with VEX support.",
                how="Walks build tools (Maven, Gradle, sbt, Bazel, pnpm, yarn) and resolves transitive deps. CycloneDX 1.5 + VEX output.",
                when="Monorepos where Syft misses transitive deps. CycloneDX standard.",
                pros="Deep coverage in Maven/Gradle/Bazel. CycloneDX 1.5 + VEX.",
                cons="Requires the build toolchain installed for the best result. Slower than Syft.",
                alts="Syft (simpler, multi-format), Microsoft SBOM Tool, Tern."),
    "retire": dict(type="Vuln JS (hash/version)", mode="static", since="2013",
                author="Erlend Oftedal", license="Apache-2.0", covers=["cve"],
                what="retire.js: detects vulnerable JS libs by matching the hash/version of the .js files.",
                how="Scans the FS for .js and matches against a DB of vulnerable versions/hashes (jQuery <3.5 → CVE-X). Independent of package.json.",
                when="Catches CDN-vendored JS, copied builds, minified libs that package.json does not capture. Client-heavy webapps.",
                pros="Detects vendored libs outside the dependency manifest. Database curated over years.",
                cons="Client-side JS only. Does not detect custom-coded vulns. The DB depends on community maintenance.",
                alts="Trivy (but package.json-only), npm audit, Snyk."),
    "whispers": dict(type="Secrets (structured configs)", mode="static", since="2019",
                author="Adam Listek (independent)", license="Apache-2.0", covers=["secrets"],
                what="Whispers: a parser for structured configs (YAML/JSON/Dockerfile) instead of regex over opaque text.",
                how="Parses the format (YAML/JSON/Dockerfile/.env/etc) and extracts values of named keys (password, api_key, secret). Plugin-based.",
                when="K8s manifests, Helm values.yaml, Dockerfiles, .env. Good signal-to-noise vs. pure regex.",
                pros="Structure-aware: fewer FPs than regex on YAML/JSON. Extensible plugins.",
                cons="Does not cover unstructured formats (logs, scripts).",
                alts="TruffleHog, GitLeaks, detect-secrets."),
    "kube-linter": dict(type="K8s manifest issues", mode="static", since="2020",
                author="StackRox / Red Hat", license="Apache-2.0", covers=["misconfig"],
                what="StackRox kube-linter: lints Kubernetes YAMLs for security best practices.",
                how="Parses YAML/Helm and runs declarative checks (run-as-root, resource limits, network policies, privileged, hostPath). 30+ built-in rules.",
                when="Images that bundle Helm charts or k8s manifests for deployment. Complements Trivy --scanners config.",
                pros="K8s-specific: covers patterns a generic linter (Trivy) misses. Backed by StackRox.",
                cons="Skips silently if the image carries no YAML.",
                alts="Trivy --scanners config, Checkov, Polaris."),
    "hadolint": dict(type="Dockerfile lint", mode="static", since="2015",
                author="Lukas Martinelli", license="MIT", covers=["misconfig"],
                what="Hadolint: a Dockerfile linter with best-practice rules and shellcheck on the RUN lines.",
                how="Reconstructs the Dockerfile from docker history --no-trunc. Applies DL/SC rules. SARIF/JSON/TTY output.",
                when="Static Dockerfile auditing outside the build. Useful in compliance (CIS Docker).",
                pros="Shellcheck on the RUNs detects classes of bugs other linters miss.",
                cons="Dockerfile reconstruction via history loses COPY/ADD targets — limits the analysis.",
                alts="Dockle (focuses on CIS, not shellcheck), Trivy --scanners config."),
    "checkov": dict(type="IaC misconfig", mode="static", since="2019",
                author="Bridgecrew / Prisma", license="Apache-2.0", covers=["iac", "misconfig"],
                what="Checkov: 1000+ IaC + Dockerfile + SCA misconfig policies.",
                how="Parses Terraform, CloudFormation, Kubernetes, Helm, ARM, Bicep, OpenAPI, Dockerfile, Serverless, GH Actions. Runs Python+YAML rules.",
                when="Images that carry packaged IaC. Standard in DevSecOps pipelines.",
                pros="Broader coverage than Trivy/Dockle. Maintained by Bridgecrew (Palo Alto). Custom policies in Python.",
                cons="Heavy: 700MB image. Can have FPs with very broad coverage.",
                alts="Trivy --scanners config (smaller subset), tfsec (Terraform-only), KICS."),
    "pip-audit": dict(type="Vuln Python (PyPA)", mode="static", since="2022",
                author="PyPA / Trail of Bits", license="Apache-2.0", covers=["cve"],
                what="pip-audit: an authoritative Python CVE scanner, uses the PyPA Advisory DB.",
                how="Reads requirements.txt or installed site-packages; matches against pypa/advisory-database. Supports yanked release flags.",
                when="A per-ecosystem alternative to Trivy/Grype for Python. Recommended by PyPA itself.",
                pros="Direct authority (PyPA). Detects yanked releases (Trivy does not).",
                cons="Python only. Less coverage than Trivy on multi-language images.",
                alts="Safety (commercial), Snyk, Trivy."),
    "httpx": dict(type="Web fingerprint+probe", mode="dynamic", since="2020",
                author="ProjectDiscovery", license="MIT", covers=["fingerprint", "web"],
                what="httpx: a fast web prober from ProjectDiscovery — fingerprint, TLS, JARM, CDN.",
                how="An HTTP client optimized in Go. -tech-detect for Wappalyzer-style, -tls-grab, -jarm, -cdn, -favicon. JSONL output.",
                when="Initial recon: a more robust alternative to WhatWeb. Pipeline-friendly (JSONL).",
                pros="Fast. Multi-feature in a single binary. Maintained (ProjectDiscovery).",
                cons="Fingerprint only, not a vuln scan.",
                alts="WhatWeb (Ruby, slower), Wappalyzer CLI."),
    "jaeles": dict(type="Web Vuln (signatures)", mode="dynamic", since="2019",
                author="j3ssie", license="MIT", covers=["web"],
                what="Jaeles: a template-driven web scanner, similar to Nuclei.",
                how="Loads YAML signatures from the j3ssie/jaeles-signatures DB and runs them against a URL. Matcher engine (regex/diff/length).",
                when="Cross-validation with Nuclei. Tsunami was the 1st option but its image is private on GHCR.",
                pros="Template-driven (similar to Nuclei). Open-source.",
                cons="Smaller community than Nuclei. Templates require `jaeles config init` on the 1st run.",
                alts="Nuclei (more active), Tsunami (private image), Wapiti."),
    "arachni": dict(type="Web App (DAST)", mode="dynamic", since="2010",
                author="Tasos Laskos (Sarosys)", license="Arachni Public Source",
                covers=["web"],
                what="Arachni: a Ruby DAST framework with deep checks for SQLi/XSS/RFI/LFI.",
                how="Crawl + detection plug-ins (audits) + meta plug-ins. Parallel via processes. AFR (binary) + JSON/HTML reporters output.",
                when="Cross-validation with ZAP. Independent plugins — useful as a 3rd opinion.",
                pros="A complete suite (similar to ZAP). Orthogonal plugins. Detects SQLi/XSS/RFI/LFI/CSRF/etc.",
                cons="Archived project (last release 2017). Receives no new vulns since then.",
                alts="OWASP ZAP, Burp Suite (commercial), Wapiti."),
    "testssl": dict(type="TLS/SSL audit", mode="dynamic", since="2014",
                author="Dirk Wetter", license="GPLv2", covers=["network"],
                what="testssl.sh: a comprehensive TLS/SSL audit via OpenSSL.",
                how="Bash + a custom OpenSSL build (includes exploits removed from upstream). Tests 100+ checks: cipher suites, famous vulns (Heartbleed, POODLE, BEAST, LOGJAM, FREAK, ROBOT), HSTS, certs.",
                when="Auditing an HTTPS endpoint — a signal fully orthogonal to the HTTP-layer scanners.",
                pros="More detailed than Nessus/OpenVAS for TLS. Standalone Bash — easy to audit.",
                cons="Bash-only (slow compared to Go tools). HTTP targets return a baseline 'no TLS' — useful but thin.",
                alts="sslyze, sslscan, Qualys SSL Labs."),
}


# ────────────────────────────────────────────────────────────────────────────
# Findings counters (best-effort, per scanner)
# ────────────────────────────────────────────────────────────────────────────

def _safe_json(p):
    if not p or not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace") or "null")
    except Exception:
        return None


def _count_lines(p):
    if not p or not p.exists():
        return 0
    try:
        return sum(1 for ln in p.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip())
    except Exception:
        return 0


def count_findings(scanner, target, sdir):
    if not sdir.exists():
        return 0, {}
    p = lambda *names: next((sdir / n for n in names if (sdir / n).exists()), None)
    severities = {}

    if scanner == "osv":
        f = p(f"{target}-osv.json")
        d = _safe_json(f)
        if isinstance(d, dict):
            n = sum(len(r.get("packages", [])) for r in d.get("results", []))
            return n, severities
    if scanner == "yara":
        f = p(f"{target}-yara.txt")
        return _count_lines(f), severities
    if scanner == "detect-secrets":
        f = p(f"{target}-detect-secrets.json")
        d = _safe_json(f)
        if isinstance(d, dict):
            return sum(len(v) for v in (d.get("results") or {}).values()), severities
    if scanner == "guarddog":
        f = p(f"{target}-guarddog.jsonl")
        return _count_lines(f), severities
    if scanner == "govulncheck":
        f = p(f"{target}-govulncheck.json")
        if not f or not f.exists():
            return 0, severities
        return _count_lines(f) // 5, severities
    if scanner == "clair":
        return 0, severities  # output empty in our runs
    if scanner == "dependency-check":
        f = p("dependency-check-report.json")
        d = _safe_json(f)
        if isinstance(d, dict):
            n = sum(len(dep.get("vulnerabilities", []))
                    for dep in d.get("dependencies", []))
            return n, severities
        return 0, severities
    if scanner == "cdxgen":
        f = p(f"{target}-cdxgen.cdx.json")
        d = _safe_json(f)
        if isinstance(d, dict):
            return len(d.get("components", [])), severities
    if scanner == "retire":
        f = p(f"{target}-retire.json")
        d = _safe_json(f)
        if isinstance(d, list):
            return sum(len(c.get("results", [])) for c in d), severities
    if scanner == "whispers":
        f = p(f"{target}-whispers.json")
        return _count_lines(f), severities
    if scanner == "kube-linter":
        f = p(f"{target}-kube-linter.json")
        d = _safe_json(f)
        if isinstance(d, dict):
            return len(d.get("Reports", []) or d.get("reports", [])), severities
    if scanner == "secretscanner":
        return 0, severities
    if scanner == "hadolint":
        f = p(f"{target}-hadolint.json")
        d = _safe_json(f)
        if isinstance(d, list):
            for it in d:
                lvl = (it.get("level") or "").lower()
                severities[lvl] = severities.get(lvl, 0) + 1
            return len(d), severities
    if scanner == "checkov":
        f = p(f"{target}-checkov.json")
        d = _safe_json(f)
        if isinstance(d, dict):
            res = (d.get("results") or {}).get("failed_checks", [])
            return len(res), severities
        if isinstance(d, list):
            n = sum(len((r.get("results") or {}).get("failed_checks", [])) for r in d)
            return n, severities
    if scanner == "pip-audit":
        f = p(f"{target}-pip-audit.txt")
        if f:
            txt = f.read_text(encoding="utf-8", errors="replace")
            return len(re.findall(r"^\S+\s+[0-9]\S*\s+\S+", txt, re.M)), severities
    if scanner == "httpx":
        f = p(f"{target}-httpx.jsonl")
        return _count_lines(f), severities
    if scanner == "jaeles":
        f = p(f"{target}-jaeles.json")
        if f and f.stat().st_size > 0:
            return f.read_text(encoding="utf-8").count('"vuln_url"'), severities
    if scanner == "arachni":
        f = p(f"{target}-arachni.json")
        d = _safe_json(f)
        if isinstance(d, dict):
            return len(d.get("issues", [])), severities
    if scanner == "testssl":
        f = p(f"{target}-testssl.json")
        d = _safe_json(f)
        if isinstance(d, list):
            for it in d:
                lvl = (it.get("severity") or "").lower()
                severities[lvl] = severities.get(lvl, 0) + 1
            return len(d), severities
    if scanner == "openvas":
        f = p(f"{target}-openvas.xml")
        if f:
            txt = f.read_text(encoding="utf-8", errors="replace")
            counts = {}
            for tag in ("critical", "high", "medium", "low", "log", "false_positive"):
                m = re.search(rf"<{tag}><full>(\d+)</full>", txt)
                if m:
                    counts[tag] = int(m.group(1))
            total_m = re.search(r"<result_count>(\d+)", txt)
            total = int(total_m.group(1)) if total_m else sum(counts.values())
            return total, counts
    return 0, severities


# ────────────────────────────────────────────────────────────────────────────
# Aggregation
# ────────────────────────────────────────────────────────────────────────────

def collect_data():
    """Build a DATA-shaped dict for each new scanner."""
    out = {}
    for scanner, info in INFO.items():
        wall_per_target = {}
        by_target_findings = {}
        cpu_max = 0.0
        mem_max = 0.0
        any_ran = False
        sev_total = {}
        for tgt in TARGETS:
            best = None
            for host in HOSTS:
                # OpenVAS: only node1 has the successful run; node2 errored.
                if scanner == "openvas" and host == "node2":
                    continue
                metrics_file = SCANS_OUT / host / tgt / f"{tgt}-metrics.json"
                if not metrics_file.exists():
                    continue
                try:
                    entries = json.loads(metrics_file.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    continue
                for e in entries:
                    if e.get("scanner") == scanner:
                        # Prefer ok status
                        if best is None or (e.get("status") == "ok"
                                            and best.get("status") != "ok"):
                            best = {**e, "host": host}
                        break
            if best is None:
                continue
            any_ran = True
            sdir = SCANS_OUT / best["host"] / tgt / scanner
            findings, sev = count_findings(scanner, tgt, sdir)
            wall_per_target[tgt] = round(best.get("wall_seconds", 0), 2)
            by_target_findings[tgt] = findings
            cpu_max = max(cpu_max, best.get("peak_cpu_percent", 0))
            mem_max = max(mem_max, best.get("peak_mem_mb", 0))
            for k, v in sev.items():
                sev_total[k] = sev_total.get(k, 0) + v
        if not any_ran:
            continue
        wall_avg = (sum(wall_per_target.values()) / len(wall_per_target)
                    if wall_per_target else None)
        out[scanner] = {
            "name": scanner,
            "mode": info["mode"],
            "type": info["type"],
            "wall_avg": wall_avg,
            "cpu_max": cpu_max,
            "mem_max": mem_max,
            "wall_per_target": wall_per_target,
            "findings": sum(by_target_findings.values()),
            "severities": sev_total,
            "by_target_findings": by_target_findings,
            "covers": info["covers"],
            "ran": True,
        }
    return out


# ────────────────────────────────────────────────────────────────────────────
# HTML fragment builders
# ────────────────────────────────────────────────────────────────────────────

def fmt_badge(n):
    if not n:
        return ""
    if n >= 1000:
        return f'<span class="badge">{n // 1000}.{n % 1000:03d}</span>'
    return f'<span class="badge">{n}</span>'


def build_calc_toggles(data):
    parts = []
    for s in sorted(data.keys()):
        mode = data[s]["mode"]
        tag = "static" if mode == "static" else "dynamic"
        letter = "s" if mode == "static" else "d"
        parts.append(
            f'        <label class="calc-toggle" data-scanner="{html.escape(s)}">\n'
            f'          <input type="checkbox">\n'
            f'          <span>{html.escape(s)}</span>\n'
            f'          <span class="tag {tag}">{letter}</span>\n'
            f'        </label>'
        )
    return "\n".join(parts)


def build_tab_buttons(data):
    parts = []
    for s in sorted(data.keys()):
        n = data[s]["findings"]
        parts.append(
            f'<button class="tab" role="tab" id="tabbtn-{html.escape(s)}" '
            f'aria-controls="tab-{html.escape(s)}" aria-selected="false" tabindex="-1">'
            f'{html.escape(s)}{fmt_badge(n)}</button>'
        )
    return "".join(parts)


def build_panel(s, info, entry):
    mode = entry["mode"]
    type_ = entry["type"]
    findings = entry["findings"]
    by_t = entry["by_target_findings"]
    severities = entry["severities"]
    sev_html = ""
    if severities:
        items = sorted(severities.items(), key=lambda kv: -kv[1])
        sev_html = ("<dt>Severidades</dt><dd>"
                    + ", ".join(f"<b>{k}</b>: {v}" for k, v in items)
                    + "</dd>")
    by_target_html = ", ".join(f"<b>{html.escape(t)}</b>: {by_t.get(t, 0)}" for t in TARGETS)
    return (
        f'</div><div id="tab-{html.escape(s)}" class="tab-panel" '
        f'role="tabpanel" aria-labelledby="tabbtn-{html.escape(s)}" hidden>\n'
        f'          <div class="header">\n'
        f'            <div>\n'
        f'              <h3>{html.escape(type_)} — {html.escape(s)}</h3>\n'
        f'              <div class="meta">{html.escape(info["what"])} '
        f'· <a href="https://github.com/search?q={html.escape(s)}" '
        f'target="_blank" rel="noopener">repo</a></div>\n'
        f'            </div>\n'
        f'            <span class="tag {mode}">{mode}</span>\n'
        f'          </div>\n'
        f'    <section class="scanner-info" aria-label="About the {html.escape(s)} scanner">\n'
        f'      <div class="meta-row">\n'
        f'        <span>since<b>{html.escape(info["since"])}</b></span>\n'
        f'        <span>author<b>{html.escape(info["author"])}</b></span>\n'
        f'        <span>license<b>{html.escape(info["license"])}</b></span>\n'
        f'        <span>type<b>{html.escape(info["type"])}</b></span>\n'
        f'        <span>mode<b>{html.escape(info["mode"])}</b></span>\n'
        f'      </div>\n'
        f'      <dl>\n'
        f'        <dt>What it is</dt><dd>{html.escape(info["what"])}</dd>\n'
        f'        <dt>How it works</dt><dd>{html.escape(info["how"])}</dd>\n'
        f'        <dt>When to use</dt><dd>{html.escape(info["when"])}</dd>\n'
        f'        <dt>+ Strengths</dt><dd style="color:#0d6e3e">{html.escape(info["pros"])}</dd>\n'
        f'        <dt>− Limitations</dt><dd style="color:#92400e">{html.escape(info["cons"])}</dd>\n'
        f'        <dt>Alternatives</dt><dd>{html.escape(info["alts"])}</dd>\n'
        f'        <dt>Total findings</dt><dd><b>{findings}</b> '
        f'({by_target_html}){sev_html}</dd>\n'
        f'      </dl>\n'
        f'    </section>'
    )


COVERAGE_COLS = ["sbom", "cve", "secrets", "misconfig", "iac", "web",
                 "network", "fingerprint", "malware", "supplychain"]
# Note original matrix uses these display columns:
DISPLAY_COLS = [("SBOM", "sbom"), ("CVE", "cve"), ("Secrets", "secrets"),
                ("Misconfig", "misconfig"), ("IaC", "iac"), ("Web/DAST", "web"),
                ("Network", "network"), ("Recon", "fingerprint"),
                ("Malware", "malware")]


def build_matrix_rows(data):
    parts = []
    for s in sorted(data.keys()):
        e = data[s]
        cells = [f'<td><strong>{html.escape(s)}</strong></td>'
                 f'<td><span class="tag {e["mode"]}">{e["mode"]}</span></td>']
        for _, key in DISPLAY_COLS:
            mark = "yes" if key in e["covers"] else "no"
            symbol = "●" if mark == "yes" else "·"
            cells.append(f'<td><span class={mark}>{symbol}</span></td>')
        parts.append("<tr>" + "".join(cells) + "</tr>")
    return "".join(parts)


# ────────────────────────────────────────────────────────────────────────────
# Surgical injection
# ────────────────────────────────────────────────────────────────────────────

def inject(content, data):
    # 1. Update DATA dict (line 1111). Find prefix `const DATA = ` and replace
    #    the JSON object up to its closing `};\n` boundary.
    m = re.search(r"const DATA = (\{.*?\});\n", content, flags=re.S)
    if not m:
        raise RuntimeError("DATA = {...} literal not found")
    existing = json.loads(m.group(1))
    existing.update(data)
    new_json = json.dumps(existing, ensure_ascii=False)
    content = content[:m.start()] + f"const DATA = {new_json};\n" + content[m.end():]

    # 2. calc-toggles: append before the closing `</div>` after the zap toggle.
    toggles = build_calc_toggles(data)
    pat = (r'(        <label class="calc-toggle" data-scanner="zap">\n'
           r'          <input type="checkbox">\n'
           r'          <span>zap</span>\n'
           r'          <span class="tag dynamic">d</span>\n'
           r'        </label>)(</div>)')
    repl = r'\1\n' + toggles + r'\2'
    content, n = re.subn(pat, repl, content, count=1)
    if n != 1:
        raise RuntimeError("calc-toggle anchor not matched")

    # 3. tab buttons: append after the openvas button on line 466.
    buttons = build_tab_buttons(data)
    anchor = ('<button class="tab" role="tab" id="tabbtn-openvas" '
              'aria-controls="tab-openvas" aria-selected="false" tabindex="-1">'
              'openvas</button>')
    if anchor not in content:
        raise RuntimeError("openvas tab button anchor not found")
    content = content.replace(anchor, anchor + buttons, 1)

    # 4. panels: insert after the openvas tab-panel closes (the </div> right
    #    before `</div>` ending the per-scanner main section).
    panels = "\n".join(build_panel(s, INFO[s], data[s])
                       for s in sorted(data.keys()))
    panel_anchor = ('        <dt>Alternatives</dt>'
                    '<dd>Nessus (commercial, more polished), Tenable.io (cloud), '
                    'Qualys, Rapid7 InsightVM.</dd>\n      </dl>\n'
                    '    </section>\n        </div>\n  </div>\n</section>')
    if panel_anchor not in content:
        raise RuntimeError("openvas panel close anchor not found — adjust replacement string")
    insertion = ('        <dt>Alternatives</dt>'
                 '<dd>Nessus (commercial, more polished), Tenable.io (cloud), '
                 'Qualys, Rapid7 InsightVM.</dd>\n      </dl>\n'
                 '    </section>\n' + panels + '\n        </div>\n  </div>\n</section>')
    content = content.replace(panel_anchor, insertion, 1)

    # 5. coverage matrix rows — append before </tbody></table>.
    matrix_rows = build_matrix_rows(data)
    matrix_anchor = ('<tr><td><strong>zap</strong></td>'
                     '<td><span class="tag dynamic">dynamic</span></td>')
    end_marker = "</tbody></table>"
    # Find the closing </tbody> right after the zap row and insert matrix_rows
    # in front of </tbody>.
    matrix_close = '</tbody></table>'
    # Locate the FIRST </tbody></table> after the matrix's known zap row.
    idx = content.find(matrix_anchor)
    if idx == -1:
        raise RuntimeError("matrix zap row not found")
    close_idx = content.find(matrix_close, idx)
    if close_idx == -1:
        raise RuntimeError("matrix </tbody></table> not found after zap row")
    content = content[:close_idx] + matrix_rows + content[close_idx:]

    # 6. update Por scanner badge from 14 → new total (14 + new)
    new_count = 14 + len(data)
    content = content.replace(
        '<span class="badge">14</span></button>\n    <button class="maintab"',
        f'<span class="badge">{new_count}</span></button>\n    <button class="maintab"',
        1,
    )
    return content


def main():
    content = HTML_PATH.read_text(encoding="utf-8")
    data = collect_data()
    print(f"collected {len(data)} new scanners with data")
    content = inject(content, data)
    HTML_PATH.write_text(content, encoding="utf-8")
    print(f"updated {HTML_PATH.relative_to(ROOT)} ({len(content)} chars)")
    if NEW_HTML.exists():
        NEW_HTML.unlink()
        print(f"removed {NEW_HTML.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
