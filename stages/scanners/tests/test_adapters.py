import json

from scanners.adapters.registry import load_registry, select
from scanners.adapters import trivy, grype, nuclei, dependency_check, semgrep, yara, clamav, osv
from scanners.models import Category, Mode, Severity, Target

T = Target("nginx:1.12", name="nginx", ip="172.28.0.7")


def test_registry_loads_and_renders(tmp_path):
    reg = load_registry("config/scanners.yaml")
    assert {"trivy", "grype", "syft", "osv", "dockle", "trufflehog", "nuclei", "nikto", "zap"} <= set(reg)
    spec = reg["trivy"]
    assert spec.mode is Mode.STATIC and spec.user == "0:0" and spec.needs_tarball
    r = spec.render({"image": "nginx:1.12", "name": "nginx", "out": "/out", "tarball": "/work/image.tar"})
    assert "/work/image.tar" in r.argv and "/out/nginx.trivy.json" in r.argv
    assert r.outputs == ["nginx.trivy.json"] and r.extra and "/work/image.tar" in r.extra[0]
    static = select(reg, only=[], skip=[], static=True, dynamic=False)
    assert all(s.mode is Mode.STATIC for s in static) and reg["nuclei"] not in static


def test_trivy_parse(tmp_path):
    doc = {"Results": [
        {"Target": "nginx (debian 11)", "Type": "debian", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2023-1234", "PkgName": "openssl", "InstalledVersion": "1.1.1",
             "FixedVersion": "1.1.1n", "Severity": "HIGH", "Title": "ssl bug",
             "CVSS": {"nvd": {"V3Score": 7.5}}, "References": ["https://x"]}]},
        {"Target": "Dockerfile", "Misconfigurations": [
            {"ID": "DS002", "Title": "root user", "Severity": "MEDIUM", "Message": "runs as root"}]},
    ]}
    (tmp_path / "nginx.trivy.json").write_text(json.dumps(doc))
    fs = trivy.parse(tmp_path, T)
    assert len(fs) == 2
    v = next(f for f in fs if f.category is Category.PKG_VULN)
    assert v.id == "CVE-2023-1234" and v.package == "openssl" and v.cvss == 7.5
    assert v.severity is Severity.HIGH and v.target_ip == "172.28.0.7" and v.cves == ["CVE-2023-1234"]
    assert any(f.category is Category.IMAGE_CONFIG for f in fs)


def test_grype_parse(tmp_path):
    doc = {"matches": [
        {"vulnerability": {"id": "CVE-2022-9", "severity": "Critical",
                           "cvss": [{"metrics": {"baseScore": 9.8}}], "fix": {"versions": ["2.0"]},
                           "urls": ["https://y"]},
         "artifact": {"name": "zlib", "version": "1.2.11", "type": "deb",
                      "locations": [{"path": "/usr/lib/zlib"}]}}]}
    (tmp_path / "nginx.grype.json").write_text(json.dumps(doc))
    fs = grype.parse(tmp_path, T)
    assert len(fs) == 1 and fs[0].id == "CVE-2022-9" and fs[0].severity is Severity.CRITICAL
    assert fs[0].cvss == 9.8 and fs[0].fixed_version == "2.0" and fs[0].package == "zlib"


def test_nuclei_parse(tmp_path):
    lines = [json.dumps({"template-id": "CVE-2021-44228", "host": "172.28.0.7:8080",
                         "matched-at": "http://172.28.0.7:8080/", "info": {
                             "name": "log4shell", "severity": "critical",
                             "classification": {"cve-id": ["CVE-2021-44228"], "cvss-score": 10.0}}})]
    (tmp_path / "nginx.nuclei.jsonl").write_text("\n".join(lines))
    fs = nuclei.parse(tmp_path, T)
    assert len(fs) == 1
    f = fs[0]
    assert f.category is Category.WEB_VULN and f.severity is Severity.CRITICAL
    assert f.endpoint == "172.28.0.7:8080" and "CVE-2021-44228" in f.cves and f.cvss == 10.0
    assert f.target_ip == "172.28.0.7"


def test_dependency_check_parse(tmp_path):
    doc = {"dependencies": [
        {"fileName": "spring-core-4.3.jar", "packages": [{"id": "pkg:maven/org.springframework/spring-core@4.3"}],
         "vulnerabilities": [
            {"name": "CVE-2018-1270", "severity": "HIGH", "cvssv3": {"baseScore": 9.8},
             "cwes": ["CWE-94"], "description": "Spring RCE",
             "references": [{"url": "https://nvd.example/CVE-2018-1270"}]}]},
        {"fileName": "foo.jar", "vulnerabilities": []},
    ]}
    (tmp_path / "dependency-check-report.json").write_text(json.dumps(doc))
    fs = dependency_check.parse(tmp_path, T)
    assert len(fs) == 1
    f0 = fs[0]
    assert f0.id == "CVE-2018-1270" and f0.severity is Severity.HIGH and f0.cvss == 9.8
    assert f0.category is Category.PKG_VULN and f0.ecosystem == "maven" and f0.target_ip == "172.28.0.7"
    assert "org.springframework/spring-core" in f0.package and f0.cves == ["CVE-2018-1270"]


def test_semgrep_parse(tmp_path):
    doc = {"results": [
        {"check_id": "python.lang.security.audit.dangerous-system-call", "path": "/scan/app/main.py",
         "start": {"line": 12}, "extra": {"severity": "ERROR", "message": "os.system with user input",
                                          "metadata": {"cwe": "CWE-78", "owasp": "A03:2021"}, "lines": "os.system(cmd)"}},
        {"check_id": "generic.secrets.security.detected-aws-secret-key", "path": "/scan/cfg.env",
         "start": {"line": 3}, "extra": {"severity": "WARNING", "message": "AWS secret key", "metadata": {}}},
    ]}
    (tmp_path / "nginx.semgrep.json").write_text(json.dumps(doc))
    fs = semgrep.parse(tmp_path, T)
    assert len(fs) == 2
    sast = next(x for x in fs if x.category is Category.OTHER)
    assert sast.severity is Severity.HIGH and sast.location == "app/main.py:12" and sast.target_ip == "172.28.0.7"
    sec = next(x for x in fs if x.category is Category.SECRET)
    assert sec.severity is Severity.MEDIUM


def test_yara_parse(tmp_path):
    (tmp_path / "nginx.yara.txt").write_text(
        "MALW_Eicar /scan/usr/share/test/eicar.com\n"
        "0x0:$a: X5O!P%@AP[4\\PZX54(P^)7CC)7}\n"
        "Suspicious_Base64 /scan/opt/app/run.sh\n")
    fs = yara.parse(tmp_path, T)
    assert len(fs) == 2
    f0 = next(x for x in fs if x.id == "MALW_Eicar")
    assert f0.category is Category.MALWARE and f0.location == "usr/share/test/eicar.com" and f0.target_ip == "172.28.0.7"
    assert "X5O" in f0.description


def test_clamav_parse(tmp_path):
    (tmp_path / "nginx.clamav.txt").write_text(
        "/scan/tmp/x.bin: Win.Test.EICAR_HDB-1 FOUND\n"
        "/scan/var/log/clean.log: OK\n")
    fs = clamav.parse(tmp_path, T)
    assert len(fs) == 1 and fs[0].category is Category.MALWARE
    assert fs[0].id == "Win.Test.EICAR_HDB-1" and fs[0].location == "tmp/x.bin"


def test_osv_parse_cvss_vector_high(tmp_path):
    # CVE-2019-1543: NVD scores this CVSS:3.0/...:H/I:H/A:N at 7.4 (HIGH).
    doc = {"results": [{"source": {"path": "/lib/libssl.so.1.1"}, "packages": [{
        "package": {"name": "openssl", "version": "1.1.1a", "ecosystem": "Alpine"},
        "vulnerabilities": [{
            "id": "ALPINE-CVE-2019-1543", "aliases": ["CVE-2019-1543"],
            "summary": "ChaCha20-Poly1305 nonce reuse",
            "severity": [{"type": "CVSS_V3",
                          "score": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"}],
            "references": [{"url": "https://nvd.example/CVE-2019-1543"}],
        }],
    }]}]}
    (tmp_path / "nginx.osv.json").write_text(json.dumps(doc))
    fs = osv.parse(tmp_path, T)
    assert len(fs) == 1
    f0 = fs[0]
    assert f0.category is Category.PKG_VULN and f0.id == "CVE-2019-1543"
    assert f0.severity is Severity.HIGH and f0.cvss == 7.4
    assert f0.package == "openssl" and f0.cves == ["CVE-2019-1543"]


def test_osv_parse_cvss_vector_low(tmp_path):
    doc = {"results": [{"source": {"path": "x"}, "packages": [{
        "package": {"name": "p", "version": "1", "ecosystem": "Alpine"},
        "vulnerabilities": [{"id": "X-1", "aliases": [],
            "severity": [{"type": "CVSS_V3",
                          "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}]}],
    }]}]}
    (tmp_path / "nginx.osv.json").write_text(json.dumps(doc))
    fs = osv.parse(tmp_path, T)
    assert len(fs) == 1 and fs[0].severity is Severity.LOW and 0 < fs[0].cvss < 4


def test_osv_parse_database_specific_fallback(tmp_path):
    # No `severity[]` at all — most OSV findings look like this. Must fall
    # back to the qualitative `database_specific.severity` (GHSA-style).
    doc = {"results": [{"source": {"path": "x"}, "packages": [{
        "package": {"name": "p", "version": "1", "ecosystem": "PyPI"},
        "vulnerabilities": [{"id": "GHSA-aaa", "aliases": [],
            "database_specific": {"severity": "MODERATE"}}],
    }]}]}
    (tmp_path / "nginx.osv.json").write_text(json.dumps(doc))
    fs = osv.parse(tmp_path, T)
    assert len(fs) == 1 and fs[0].severity is Severity.MEDIUM and fs[0].cvss is None


def test_osv_parse_no_severity_is_unknown(tmp_path):
    doc = {"results": [{"source": {"path": "x"}, "packages": [{
        "package": {"name": "p", "version": "1", "ecosystem": "Alpine"},
        "vulnerabilities": [{"id": "Z-1", "aliases": []}],
    }]}]}
    (tmp_path / "nginx.osv.json").write_text(json.dumps(doc))
    fs = osv.parse(tmp_path, T)
    assert len(fs) == 1 and fs[0].severity is Severity.UNKNOWN and fs[0].cvss is None
