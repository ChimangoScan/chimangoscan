from scanners.findings.merge import dedup, worst
from scanners.models import Category, Finding, Severity


def _f(scanner, **kw):
    kw.setdefault("category", Category.PKG_VULN)
    kw.setdefault("target_name", "nginx")
    kw.setdefault("target_image", "nginx:1.12")
    return Finding(scanner=scanner, **kw)


def test_worst_severity():
    assert worst(Severity.LOW, Severity.HIGH) is Severity.HIGH
    assert worst(Severity.CRITICAL, Severity.UNKNOWN) is Severity.CRITICAL


def test_dedup_merges_across_scanners():
    a = _f("trivy", id="CVE-2021-1", package="openssl", severity=Severity.HIGH, cvss=7.5,
           cves=["CVE-2021-1"], target_ip="172.28.0.5")
    b = _f("grype", id="CVE-2021-1", package="openssl", severity=Severity.CRITICAL, cvss=9.1,
           cves=["CVE-2021-1"], references=["http://x"])
    c = _f("osv", id="CVE-2021-2", package="zlib", severity=Severity.MEDIUM)
    merged = dedup([a, b, c])
    assert len(merged) == 2
    cve1 = next(m for m in merged if m["id"] == "CVE-2021-1")
    assert cve1["found_by"] == ["grype", "trivy"] and cve1["n_scanners"] == 2
    assert cve1["severity"] == "critical" and cve1["cvss"] == 9.1
    assert cve1["target_ip"] == "172.28.0.5"        # provenance preserved
    assert "raw" not in cve1                         # merged corpus view drops the bulky raw records


def test_dedup_separates_targets():
    a = _f("trivy", id="CVE-1", package="p", target_name="nginx")
    b = _f("trivy", id="CVE-1", package="p", target_name="redis", target_image="redis:5.0")
    assert len(dedup([a, b])) == 2                   # same CVE, different containers -> distinct rows
