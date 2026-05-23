from __future__ import annotations
import csv, re
from pathlib import Path

from ..models import Category, Finding, Severity, Target

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _to_float(s) -> float | None:
    try:
        return float(s)
    except (TypeError, ValueError):
        return None


def import_openvas(path: str | Path, ip_to_target: dict[str, Target] | None = None) -> list[Finding]:
    """Fold an existing OpenVAS run into the merged view. `path` is a directory
    of reports or a single `*_completo.csv`. Findings are keyed by container IP
    so they line up with the rest of the corpus."""
    path = Path(path)
    csvs: list[Path]
    if path.is_dir():
        csvs = sorted(path.glob("*_completo.csv")) or sorted(path.rglob("*.csv"))
    else:
        csvs = [path]
    ip_to_target = ip_to_target or {}
    out: list[Finding] = []
    seen: set[tuple] = set()
    for c in csvs:
        try:
            rows = list(csv.DictReader(c.open(newline="")))
        except OSError:
            continue
        for r in rows:
            ip = (r.get("IP") or r.get("Host") or "").strip()
            port = (r.get("Port") or "").strip()
            proto = (r.get("Port Protocol") or r.get("Protocol") or "").strip()
            oid = (r.get("NVT OID") or r.get("OID") or "").strip()
            name = (r.get("NVT Name") or r.get("Name") or "").strip()
            cvss = _to_float(r.get("CVSS"))
            cves = sorted(set(_CVE_RE.findall(r.get("CVEs", "") or "")))
            key = (ip, port, oid, name, r.get("Result ID", ""))
            if key in seen:
                continue
            seen.add(key)
            tgt = ip_to_target.get(ip)
            sev = Severity.parse(r.get("Severity")) if r.get("Severity") else Severity.from_cvss(cvss)
            out.append(Finding(
                scanner="openvas", category=Category.NETWORK_VULN, severity=sev,
                id=oid or (cves[0] if cves else name), title=name,
                description=(r.get("Summary") or r.get("Vulnerability Insight") or "")[:1500],
                cvss=cvss, location=f"{port}/{proto}".strip("/"),
                endpoint=f"{ip}:{port}".strip(":"), cves=cves,
                references=[u for u in re.findall(r"https?://\S+", r.get("Other References", "") or "")][:10],
                target_image=tgt.image if tgt else "", target_name=tgt.name if tgt else f"ip_{ip}",
                target_ip=ip or None,
                raw={k: v for k, v in r.items() if v}))
    return out
