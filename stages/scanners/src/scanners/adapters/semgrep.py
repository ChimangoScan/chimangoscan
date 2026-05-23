from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import f, read_json

_SEV = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}


def _strip_rootfs(path: str) -> str:
    return path[6:] if path.startswith("/scan/") else (path or "")


def _first(x):
    return x[0] if isinstance(x, list) and x else (x if isinstance(x, str) else "")


def parse(out: Path, t: Target) -> list[Finding]:
    name = next(out.glob("*.semgrep.json"), None)
    doc = read_json(name) if name else None
    if not isinstance(doc, dict):
        return []
    res = []
    for r in doc.get("results") or []:
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        check = r.get("check_id") or ""
        is_secret = "secret" in check.lower() or "secret" in str(meta.get("category", "")).lower()
        res.append(f("semgrep", t, category=Category.SECRET if is_secret else Category.OTHER,
                     severity=_SEV.get(str(extra.get("severity", "")).upper(), Severity.parse(extra.get("severity"))),
                     id=check.split(".")[-1][:80] or check[:80], title=(extra.get("message") or check)[:200],
                     description=(extra.get("message") or "").strip()[:1000],
                     location=f"{_strip_rootfs(r.get('path', ''))}:{(r.get('start') or {}).get('line', '')}".rstrip(":"),
                     references=[u for u in [_first(meta.get("references")), meta.get("source")] if u][:10],
                     raw={"check_id": check, "severity": extra.get("severity"),
                          "cwe": meta.get("cwe"), "owasp": meta.get("owasp"),
                          "technology": meta.get("technology"), "lines": extra.get("lines", "")[:300]}))
    return res
