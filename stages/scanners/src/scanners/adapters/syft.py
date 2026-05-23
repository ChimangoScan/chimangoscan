from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import f, read_json


def parse(out: Path, t: Target) -> list[Finding]:
    doc = read_json(out / f"{t.name}.syft.json")
    if not isinstance(doc, dict):
        return []
    res = []
    for a in doc.get("artifacts") or []:
        locs = [l.get("path") for l in (a.get("locations") or []) if isinstance(l, dict) and l.get("path")]
        lic = ", ".join(x for x in (a.get("licenses") or [])
                        if isinstance(x, str)) or ", ".join((x.get("value") or "") for x in
                        (a.get("licenses") or []) if isinstance(x, dict))
        res.append(f("syft", t, category=Category.SBOM_COMPONENT, severity=Severity.INFO,
                     id=a.get("purl") or f"{a.get('name')}@{a.get('version')}",
                     title=a.get("name", ""), version=a.get("version", ""),
                     package=a.get("name", ""), ecosystem=a.get("type", ""),
                     description=lic, location=locs[0] if locs else "", raw=a))
    return res
