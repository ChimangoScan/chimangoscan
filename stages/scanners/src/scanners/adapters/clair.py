from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import cves_in, f, read_json


def parse(out: Path, t: Target) -> list[Finding]:
    doc = read_json(out / f"{t.name}.clair.json")
    if not isinstance(doc, dict):
        return []
    vulns = doc.get("vulnerabilities") or {}
    items = vulns.values() if isinstance(vulns, dict) else vulns
    res = []
    for v in items:
        if not isinstance(v, dict):
            continue
        pkg = v.get("package") or {}
        name = v.get("name", "")
        res.append(f("clair", t, category=Category.PKG_VULN,
                     severity=Severity.parse(v.get("normalized_severity") or v.get("severity")),
                     id=name, title=name, description=(v.get("description") or "")[:1000],
                     package=pkg.get("name", ""), version=pkg.get("version", ""),
                     fixed_version=v.get("fixed_in_version", ""), location=v.get("repository", {}).get("name", "")
                         if isinstance(v.get("repository"), dict) else "",
                     cves=cves_in(name) or cves_in(v.get("links")),
                     references=[u for u in str(v.get("links", "")).split() if u.startswith("http")][:10],
                     raw=v))
    return res
