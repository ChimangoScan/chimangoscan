from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import endpoint_of, f, read_jsonl


def parse(out: Path, t: Target) -> list[Finding]:
    res = []
    for rec in read_jsonl(out / f"{t.name}.nuclei.jsonl"):
        if not isinstance(rec, dict):
            continue
        info = rec.get("info") or {}
        cls = info.get("classification") or {}
        cves = cls.get("cve-id") or []
        if isinstance(cves, str):
            cves = [cves]
        matched = rec.get("matched-at") or rec.get("host") or ""
        score = cls.get("cvss-score")
        res.append(f("nuclei", t, category=Category.WEB_VULN,
                     severity=Severity.parse(info.get("severity")),
                     id=rec.get("template-id") or rec.get("templateID") or "",
                     title=info.get("name", ""), description=(info.get("description") or "")[:800],
                     cvss=float(score) if isinstance(score, (int, float)) else None,
                     location=str(matched),
                     endpoint=endpoint_of(matched) or endpoint_of(rec.get("host", "")),
                     cves=[c.upper() for c in cves], references=list(info.get("reference") or [])[:10], raw=rec))
    return res
