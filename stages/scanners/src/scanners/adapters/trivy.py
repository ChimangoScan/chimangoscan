from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import cves_in, f, read_json


def _cvss(v: dict) -> float | None:
    best = None
    for vendor in (v.get("CVSS") or {}).values():
        for k in ("V3Score", "V40Score", "V2Score"):
            s = vendor.get(k) if isinstance(vendor, dict) else None
            if isinstance(s, (int, float)):
                best = max(best or 0.0, float(s))
    return best


def parse(out: Path, t: Target) -> list[Finding]:
    doc = read_json(out / f"{t.name}.trivy.json")
    if not isinstance(doc, dict):
        return []
    res = []
    for r in doc.get("Results") or []:
        loc = r.get("Target") or r.get("Class") or ""
        for v in r.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID", "")
            res.append(f("trivy", t, category=Category.PKG_VULN,
                         severity=Severity.parse(v.get("Severity")),
                         id=vid, title=v.get("Title") or vid,
                         description=(v.get("Description") or "")[:1000],
                         cvss=_cvss(v), package=v.get("PkgName", ""),
                         version=v.get("InstalledVersion", ""), fixed_version=v.get("FixedVersion", ""),
                         ecosystem=r.get("Type", ""), location=v.get("PkgPath") or loc,
                         cves=cves_in(vid) or cves_in(v.get("References")),
                         references=list(v.get("References") or [])[:10], raw=v))
        for s in r.get("Secrets") or []:
            res.append(f("trivy", t, category=Category.SECRET, severity=Severity.parse(s.get("Severity")),
                         id=s.get("RuleID", ""), title=s.get("Title") or s.get("Category", "secret"),
                         description=(s.get("Match") or "")[:300], location=f"{loc}:{s.get('StartLine', '')}",
                         raw=s))
        for m in r.get("Misconfigurations") or []:
            res.append(f("trivy", t, category=Category.IMAGE_CONFIG, severity=Severity.parse(m.get("Severity")),
                         id=m.get("ID", ""), title=m.get("Title") or m.get("ID", ""),
                         description=(m.get("Description") or m.get("Message") or "")[:600],
                         location=loc, references=list(m.get("References") or [])[:5], raw=m))
    return res
