from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import endpoint_of, f, read_json

_RISK = {"3": Severity.HIGH, "2": Severity.MEDIUM, "1": Severity.LOW, "0": Severity.INFO}


def parse(out: Path, t: Target) -> list[Finding]:
    doc = read_json(out / f"{t.name}.zap.json")
    if not isinstance(doc, dict):
        return []
    res = []
    for site in doc.get("site") or []:
        base = site.get("@name") or site.get("name") or ""
        for a in site.get("alerts") or []:
            instances = a.get("instances") or [{}]
            uri = instances[0].get("uri") or base
            cwe = a.get("cweid", "")
            res.append(f("zap", t, category=Category.WEB_VULN,
                         severity=_RISK.get(str(a.get("riskcode", "")), Severity.parse(a.get("riskdesc"))),
                         id=str(a.get("pluginid") or a.get("alertRef") or ""),
                         title=a.get("alert") or a.get("name", ""),
                         description=_strip(a.get("desc", ""))[:1000], location=uri,
                         endpoint=endpoint_of(uri) or endpoint_of(base),
                         references=[u for u in _strip(a.get("reference", "")).split() if u.startswith("http")][:10],
                         raw={**a, "cweid": cwe, "instance_count": len(instances)}))
    return res


def _strip(html: str) -> str:
    import re
    return re.sub(r"<[^>]+>", " ", html or "").replace("&amp;", "&").strip()
