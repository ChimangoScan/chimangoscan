from scanners.findings.analysis import analyze
from scanners.findings.store import CorpusStore


def _report(name, image, ip, started, finished, invs, fnds):
    return {"target": {"image": image, "name": name, "ip": ip}, "container_ip": ip,
            "started_at": started, "finished_at": finished, "open_ports": [],
            "invocations": invs, "findings": fnds, "skipped_reason": ""}


def test_analyze_markdown(tmp_path):
    f = lambda sc, **k: {"scanner": sc, "category": k.get("category", "pkg-vuln"),
                         "severity": k.get("severity", "high"), "id": k["id"],
                         "package": k.get("package", "p"), "cvss": k.get("cvss"),
                         "title": k["id"], "target_image": k["img"], "target_name": k["t"],
                         "target_ip": k.get("ip"), "endpoint": "", "cves": [k["id"]], "references": [],
                         "raw": {}}
    inv = lambda sc, st="ok", w=10.0: {"scanner": sc, "status": st, "wall_seconds": w, "peak_mem_mb": 100}
    reports = [
        _report("nginx", "nginx:1.12", "172.28.0.5", "2026-05-12T00:00:00Z", "2026-05-12T00:01:00Z",
                [inv("trivy"), inv("grype", w=20), inv("clamav", "skipped", 0)],
                [f("trivy", id="CVE-2021-1", img="nginx:1.12", t="nginx", ip="172.28.0.5"),
                 f("grype", id="CVE-2021-1", img="nginx:1.12", t="nginx", ip="172.28.0.5"),
                 f("trivy", id="CVE-2021-2", img="nginx:1.12", t="nginx", ip="172.28.0.5")]),
        _report("redis", "redis:5.0", "172.28.0.6", "2026-05-12T00:00:30Z", "2026-05-12T00:02:00Z",
                [inv("trivy"), inv("grype", "error", 0)],
                [f("trivy", id="CVE-2022-9", severity="critical", img="redis:5.0", t="redis", ip="172.28.0.6")]),
    ]
    corpus = CorpusStore(tmp_path).rebuild(reports)
    md = analyze(corpus, top=5)
    assert "# Scanner battery — analysis" in md
    assert "measure **different things**" in md          # the per-category framing
    assert "**What was measured**" in md and "`pkg-vuln`" in md and "by: grype, trivy" in md
    assert "## Per-scanner" in md and "trivy" in md and "grype" in md
    assert "## Throughput" in md and "containers / hour" in md
    assert "## Within-category agreement" in md and "### pkg-vuln" in md and "Pairwise overlap" in md
    assert "## Most exposed containers" in md and "172.28.0.5" in md and "nginx" in md
    # trivy reported CVE-2021-2 / CVE-2022-9 alone, and grype also covers pkg-vuln -> meaningful exclusives
    sline = next(l for l in md.splitlines() if l.startswith("| trivy |"))
    assert "| pkg-vuln |" in sline and "2 (2)" in sline
    tp = corpus["summary"]["throughput"]
    assert tp["wall_clock_seconds"] == 120.0 and tp["targets_per_hour"] > 0
