from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import f, read_jsonl


def _location(rec: dict) -> str:
    md = rec.get("SourceMetadata") or {}
    data = md.get("Data") or {}
    for v in data.values():
        if isinstance(v, dict):
            for key in ("file", "path", "link", "image", "layer", "Layer", "File"):
                if v.get(key):
                    return str(v[key])
    return rec.get("SourceName", "")


def parse(out: Path, t: Target) -> list[Finding]:
    res = []
    for rec in read_jsonl(out / f"{t.name}.trufflehog.jsonl"):
        if not isinstance(rec, dict) or "DetectorName" not in rec:
            continue
        verified = bool(rec.get("Verified"))
        res.append(f("trufflehog", t, category=Category.SECRET,
                     severity=Severity.CRITICAL if verified else Severity.MEDIUM,
                     id=str(rec.get("DetectorName", "")),
                     title=("verified " if verified else "") + str(rec.get("DetectorName", "secret")),
                     description=(rec.get("Redacted") or rec.get("Raw") or "")[:300],
                     location=_location(rec), raw=rec))
    return res
