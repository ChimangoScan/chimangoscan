#!/usr/bin/env python3
"""Extract structured findings from each scanner's raw output and produce a
DETAIL JS literal that the HTML page can consume for tailored visualizations.

Output: writes a JSON file at reports/scans-output/_detail.json with shape
    { "<scanner>": { "meta": {...}, "findings": [...] }, ... }

The HTML build merges this into its `const DETAIL = {...}` literal.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from base64 import b64decode
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SCANS_OUT = ROOT / "reports" / "scans-output"
OUT = SCANS_OUT / "_detail.json"

HOSTS = ["node1", "node2"]  # node1 wins for shared scanners
TARGETS = ["webgoat", "dvwa", "juice-shop"]


# ─── Helpers ────────────────────────────────────────────────────────────────

def best_dir(scanner: str, target: str) -> Path | None:
    """Return the scanner output dir for the host with non-empty data."""
    for host in HOSTS:
        d = SCANS_OUT / host / target / scanner
        if d.exists() and any(f for f in d.iterdir() if f.stat().st_size > 0):
            return d
    return None


def read_json(p: Path) -> Any:
    if not p or not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace") or "null")
    except json.JSONDecodeError:
        return None


# ─── Per-scanner extractors ────────────────────────────────────────────────

def extract_openvas() -> list[dict]:
    """OpenVAS — parse the detailed XML re-fetched from gvmd with details=1.

    The standard XML format saved by the pipeline contains only counts; we
    re-fetched a richer copy (juice-shop-openvas-detailed.xml) using
    `<get_reports details="1" .../>` against the live gvmd container.
    """
    out = []
    for tgt in TARGETS:
        d = best_dir("openvas", tgt)
        if not d:
            continue
        # Prefer the detailed XML if present
        det_file = d / f"{tgt}-openvas-detailed.xml"
        if det_file.exists():
            raw = det_file.read_text(encoding="utf-8", errors="replace")
            # Strip paramiko Cryptography warnings preceding the XML
            xml_start = raw.find("<get_reports_response")
            if xml_start > 0:
                raw = raw[xml_start:]
            try:
                tree = ET.fromstring(raw)
            except ET.ParseError:
                tree = None
            if tree is not None:
                for r in tree.iter("result"):
                    name = (r.findtext("name") or "").strip()
                    severity = (r.findtext("severity") or "0").strip()
                    threat = (r.findtext("threat") or "Log").strip()
                    host_el = r.find("host")
                    host = (host_el.text or "").strip() if host_el is not None else ""
                    port = (r.findtext("port") or "").strip()
                    nvt = r.find("nvt")
                    family = nvt.findtext("family") if nvt is not None else ""
                    cves = ""
                    if nvt is not None:
                        refs = nvt.find("refs")
                        if refs is not None:
                            cve_list = [ref.get("id", "") for ref in refs.findall("ref")
                                        if ref.get("type") == "cve"]
                            cves = ", ".join(cve_list[:3])
                    qod = ""
                    qod_el = r.find("qod/value")
                    if qod_el is not None and qod_el.text:
                        qod = qod_el.text
                    desc = (r.findtext("description") or "").strip()[:240]
                    try:
                        sev_f = float(severity)
                    except ValueError:
                        sev_f = 0.0
                    out.append({
                        "target": tgt,
                        "name": name[:120],
                        "threat": threat,
                        "severity": sev_f,
                        "host": host,
                        "port": port,
                        "family": family or "",
                        "qod": qod,
                        "cves": cves,
                        "summary": desc,
                    })
                continue
        # Fallback: parse decoded TXT (legacy)
        # Parse the decoded TXT report
        txt_file = d / f"{tgt}-openvas.txt"
        if not txt_file.exists():
            continue
        # Skip the GMP XML wrapper if base64-decoding wasn't applied yet
        raw = txt_file.read_text(encoding="utf-8", errors="replace")
        if raw.startswith("<get_reports_response"):
            m = re.search(r"</report_format>([A-Za-z0-9+/=\s]+)</report>", raw)
            if m:
                try:
                    raw = b64decode(re.sub(r"\s+", "", m.group(1))).decode(
                        "utf-8", errors="replace")
                except Exception:
                    pass
        # OpenVAS TXT report layout:
        #   Issue
        #   -----
        #   NVT:    <name>
        #   OID:    <oid>
        #   Threat: <Critical|High|Medium|Low|Log>
        #   ... etc.
        #   Severity: 7.5 (CVSS:...)
        #   Host: <ip>
        #   Port: <port>
        cur = {}
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped:
                if cur.get("nvt"):
                    out.append({
                        "target": tgt,
                        "name": cur.get("nvt", "")[:120],
                        "threat": cur.get("threat", "Log"),
                        "severity": cur.get("severity", 0.0),
                        "host": cur.get("host", ""),
                        "port": cur.get("port", ""),
                        "family": cur.get("family", ""),
                        "cves": cur.get("cves", ""),
                        "summary": cur.get("summary", "")[:200],
                    })
                cur = {}
                continue
            if stripped.startswith("NVT:"):
                cur["nvt"] = stripped[4:].strip()
            elif stripped.startswith("OID:"):
                cur["oid"] = stripped[4:].strip()
            elif stripped.startswith("Threat:"):
                cur["threat"] = stripped[7:].strip().split()[0]
            elif "Severity:" in stripped:
                m = re.search(r"Severity:\s*([0-9.]+)", stripped)
                if m:
                    try:
                        cur["severity"] = float(m.group(1))
                    except ValueError:
                        pass
            elif stripped.startswith("Host:"):
                cur["host"] = stripped[5:].strip().split()[0]
            elif stripped.startswith("Port:"):
                cur["port"] = stripped[5:].strip()
            elif stripped.startswith("Family:"):
                cur["family"] = stripped[7:].strip()
            elif stripped.startswith("CVE:"):
                cur["cves"] = stripped[4:].strip()
            elif stripped.startswith("Summary:"):
                cur["summary"] = stripped[8:].strip()
        if cur.get("nvt"):
            out.append({
                "target": tgt,
                "name": cur.get("nvt", "")[:120],
                "threat": cur.get("threat", "Log"),
                "severity": cur.get("severity", 0.0),
                "host": cur.get("host", ""),
                "port": cur.get("port", ""),
                "family": cur.get("family", ""),
                "cves": cur.get("cves", ""),
                "summary": cur.get("summary", "")[:200],
            })
    return out


def extract_osv() -> list[dict]:
    out = []
    for tgt in TARGETS:
        d = best_dir("osv", tgt)
        if not d:
            continue
        data = read_json(d / f"{tgt}-osv.json")
        if not isinstance(data, dict):
            continue
        for result in data.get("results", []):
            for pkg in result.get("packages", []):
                p = pkg.get("package", {})
                pkg_name = p.get("name", "?")
                pkg_ver = p.get("version", "?")
                ecosys = p.get("ecosystem", "?")
                for v in pkg.get("vulnerabilities", []):
                    aliases = v.get("aliases", [])
                    cve = next((a for a in aliases if a.startswith("CVE-")),
                               aliases[0] if aliases else v.get("id", "?"))
                    sev_list = v.get("severity", [])
                    cvss = 0.0
                    for s in sev_list:
                        if s.get("type", "").startswith("CVSS"):
                            try:
                                # E.g. "CVSS:3.0/AV:N/AC:L/..."
                                m = re.search(r"(\d+\.\d+)$", s.get("score", ""))
                                if m:
                                    cvss = float(m.group(1))
                            except ValueError:
                                pass
                    summary = (v.get("summary") or "").strip()[:240]
                    out.append({
                        "target": tgt,
                        "cve": cve,
                        "id": v.get("id", ""),
                        "pkg": pkg_name,
                        "version": pkg_ver,
                        "ecosystem": ecosys,
                        "summary": summary,
                        "cvss": cvss,
                    })
    return out


def extract_detect_secrets() -> list[dict]:
    out = []
    for tgt in TARGETS:
        d = best_dir("detect-secrets", tgt)
        if not d:
            continue
        data = read_json(d / f"{tgt}-detect-secrets.json")
        if not isinstance(data, dict):
            continue
        for fname, secrets in (data.get("results") or {}).items():
            for s in secrets:
                out.append({
                    "target": tgt,
                    "file": fname[:140],
                    "type": s.get("type", "?"),
                    "line_number": s.get("line_number", 0),
                    "is_verified": bool(s.get("is_verified", False)),
                })
    return out


def extract_checkov() -> list[dict]:
    out = []
    for tgt in TARGETS:
        d = best_dir("checkov", tgt)
        if not d:
            continue
        data = read_json(d / f"{tgt}-checkov.json")
        # Checkov can output a list (multi-framework run) or a single dict
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            continue
        for run in data:
            ck = (run.get("results") or {}).get("failed_checks", [])
            for c in ck:
                out.append({
                    "target": tgt,
                    "check_id": c.get("check_id", "?"),
                    "check_name": (c.get("check_name") or "")[:120],
                    "severity": (c.get("severity") or "UNKNOWN").upper(),
                    "file_path": c.get("file_path", "?"),
                    "resource": c.get("resource", "?"),
                    "framework": run.get("check_type", "?"),
                    "guideline": c.get("guideline", ""),
                })
    return out


def extract_arachni() -> list[dict]:
    out = []
    for tgt in TARGETS:
        d = best_dir("arachni", tgt)
        if not d:
            continue
        data = read_json(d / f"{tgt}-arachni.json")
        if not isinstance(data, dict):
            continue
        for issue in data.get("issues", []):
            url = (issue.get("vector", {}) or {}).get("url", "")
            method = (issue.get("vector", {}) or {}).get("method", "")
            out.append({
                "target": tgt,
                "name": issue.get("name", "?"),
                "severity": (issue.get("severity") or "informational").lower(),
                "cwe": issue.get("cwe", ""),
                "url": url[:160],
                "method": method,
                "description": (issue.get("description") or "")[:300],
            })
    return out


def extract_yara() -> list[dict]:
    out = []
    for tgt in TARGETS:
        d = best_dir("yara", tgt)
        if not d:
            continue
        f = d / f"{tgt}-yara.txt"
        if not f.exists():
            continue
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("Error:"):
                continue
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                rule, path = parts
                out.append({
                    "target": tgt,
                    "rule": rule,
                    "path": path[:160],
                })
    return out


def extract_retire() -> list[dict]:
    out = []
    for tgt in TARGETS:
        d = best_dir("retire", tgt)
        if not d:
            continue
        data = read_json(d / f"{tgt}-retire.json")
        if not isinstance(data, list):
            continue
        for c in data:
            for res in c.get("results", []):
                comp = res.get("component", "?")
                ver = res.get("version", "?")
                for v in res.get("vulnerabilities", []):
                    out.append({
                        "target": tgt,
                        "file": c.get("file", "?")[:140],
                        "component": comp,
                        "version": ver,
                        "severity": (v.get("severity") or "low").lower(),
                        "summary": (v.get("identifiers", {}).get("summary") or "")[:200],
                        "cve": ", ".join(v.get("identifiers", {}).get("CVE", [])[:2]),
                    })
    return out


def extract_testssl() -> list[dict]:
    out = []
    for tgt in TARGETS:
        d = best_dir("testssl", tgt)
        if not d:
            continue
        data = read_json(d / f"{tgt}-testssl.json")
        if not isinstance(data, list):
            continue
        for it in data:
            out.append({
                "target": tgt,
                "id": it.get("id", "?"),
                "severity": (it.get("severity") or "info").lower(),
                "finding": (it.get("finding") or "")[:240],
                "ip": it.get("ip", ""),
                "port": it.get("port", ""),
            })
    return out


def extract_hadolint() -> list[dict]:
    out = []
    for tgt in TARGETS:
        d = best_dir("hadolint", tgt)
        if not d:
            continue
        data = read_json(d / f"{tgt}-hadolint.json")
        if not isinstance(data, list):
            continue
        for it in data:
            out.append({
                "target": tgt,
                "code": it.get("code", "?"),
                "level": (it.get("level") or "info").lower(),
                "line": it.get("line", 0),
                "column": it.get("column", 0),
                "message": (it.get("message") or "")[:200],
            })
    return out


def extract_httpx() -> list[dict]:
    out = []
    for tgt in TARGETS:
        d = best_dir("httpx", tgt)
        if not d:
            continue
        f = d / f"{tgt}-httpx.jsonl"
        if not f.exists():
            continue
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            out.append({
                "target": tgt,
                "url": rec.get("url", ""),
                "status_code": rec.get("status_code", 0),
                "title": (rec.get("title") or "")[:120],
                "server": rec.get("webserver", "") or rec.get("server", ""),
                "tech": ", ".join(rec.get("tech", [])[:8]) if rec.get("tech") else "",
                "tls_grab": "yes" if rec.get("tls") else "no",
                "scheme": rec.get("scheme", ""),
                "content_type": rec.get("content_type", ""),
            })
    return out


def extract_whispers() -> list[dict]:
    out = []
    for tgt in TARGETS:
        d = best_dir("whispers", tgt)
        if not d:
            continue
        data = read_json(d / f"{tgt}-whispers.json")
        if not isinstance(data, list):
            continue
        for it in data:
            if not isinstance(it, dict):
                continue
            out.append({
                "target": tgt,
                "key": it.get("key", "?"),
                "value": (str(it.get("value", "")) or "")[:80],
                "file": (it.get("file") or "?")[:140],
                "line": it.get("line", 0),
                "rule_id": it.get("rule_id", ""),
                "severity": (it.get("severity") or "info").lower(),
            })
    return out


def extract_jaeles() -> list[dict]:
    out = []
    for tgt in TARGETS:
        d = best_dir("jaeles", tgt)
        if not d:
            continue
        # Jaeles writes per-vuln files in a subdir
        for f in d.rglob("*.json"):
            data = read_json(f)
            if not isinstance(data, dict):
                continue
            out.append({
                "target": tgt,
                "vuln_url": data.get("vuln_url", ""),
                "sign_id": data.get("sign_id", ""),
                "info": (data.get("info") or "")[:200],
            })
    return out


# ─── Orchestration ─────────────────────────────────────────────────────────

EXTRACTORS = {
    "openvas":        extract_openvas,
    "osv":            extract_osv,
    "detect-secrets": extract_detect_secrets,
    "checkov":        extract_checkov,
    "arachni":        extract_arachni,
    "yara":           extract_yara,
    "retire":         extract_retire,
    "testssl":        extract_testssl,
    "hadolint":       extract_hadolint,
    "httpx":          extract_httpx,
    "whispers":       extract_whispers,
    "jaeles":         extract_jaeles,
}


def main():
    detail = {}
    for scanner, fn in EXTRACTORS.items():
        findings = fn()
        detail[scanner] = {
            "meta": {"scanner": scanner, "targets": TARGETS},
            "findings": findings,
        }
        print(f"  {scanner:20s} {len(findings)} findings extracted")
    OUT.write_text(json.dumps(detail, ensure_ascii=False), encoding="utf-8")
    print(f"\nwrote {OUT.relative_to(ROOT)} ({OUT.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
