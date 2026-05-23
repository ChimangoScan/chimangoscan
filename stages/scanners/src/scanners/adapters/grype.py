from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import cves_in, f, read_json


def _cvss(v: dict) -> float | None:
    best = None
    for c in v.get("cvss") or []:
        m = (c.get("metrics") or {}).get("baseScore")
        if isinstance(m, (int, float)):
            best = max(best or 0.0, float(m))
    return best


def parse(out: Path, t: Target) -> list[Finding]:
    doc = read_json(out / f"{t.name}.grype.json")
    if not isinstance(doc, dict):
        return []
    res = []
    for m in doc.get("matches") or []:
        v = m.get("vulnerability") or {}
        a = m.get("artifact") or {}
        vid = v.get("id", "")
        fixv = ", ".join((v.get("fix") or {}).get("versions") or [])
        locs = [l.get("path") for l in (a.get("locations") or []) if l.get("path")]
        sev = v.get("severity")
        res.append(f("grype", t, category=Category.PKG_VULN,
                     severity=Severity.parse(sev) if sev and sev != "Unknown" else Severity.from_cvss(_cvss(v)),
                     id=vid, title=vid, description=(v.get("description") or "")[:1000], cvss=_cvss(v),
                     package=a.get("name", ""), version=a.get("version", ""), fixed_version=fixv,
                     ecosystem=a.get("type", ""), location=locs[0] if locs else "",
                     cves=cves_in(vid) or [x for x in (v.get("relatedVulnerabilities") and
                          [rv.get("id") for rv in v["relatedVulnerabilities"]] or []) if str(x).upper().startswith("CVE")],
                     references=[u.get("url") for u in (v.get("urls") or []) if isinstance(u, dict)][:10]
                                or list(v.get("urls") or [])[:10], raw=m))
    return res
