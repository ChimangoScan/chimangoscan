from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import f, read_json

_LEVEL = {"FATAL": Severity.HIGH, "WARN": Severity.MEDIUM, "INFO": Severity.LOW,
          "SKIP": Severity.INFO, "PASS": Severity.INFO, "IGNORE": Severity.INFO}


def parse(out: Path, t: Target) -> list[Finding]:
    doc = read_json(out / f"{t.name}.dockle.json")
    if not isinstance(doc, dict):
        return []
    res = []
    for d in doc.get("details") or []:
        lvl = str(d.get("level", "")).upper()
        if lvl in ("PASS", "SKIP", "IGNORE"):
            continue
        alerts = d.get("alerts") or []
        res.append(f("dockle", t, category=Category.IMAGE_CONFIG, severity=_LEVEL.get(lvl, Severity.UNKNOWN),
                     id=d.get("code", ""), title=d.get("title") or d.get("code", ""),
                     description="; ".join(str(a) for a in alerts)[:800], raw=d))
    return res
