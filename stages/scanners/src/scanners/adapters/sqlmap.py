from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import f, read_json


def parse(out: Path, t: Target) -> list[Finding]:
    """sqlmap writes a session tree under {out}; we surface any 'log' files that
    record an injection point. Best-effort — sqlmap is run targeted, not broad."""
    res = []
    for log in out.rglob("log"):
        try:
            text = log.read_text(errors="replace")
        except OSError:
            continue
        if "is vulnerable" in text or "Parameter:" in text:
            res.append(f("sqlmap", t, category=Category.WEB_VULN, severity=Severity.HIGH,
                         id="sqli", title="SQL injection confirmed by sqlmap",
                         description=text[:2000], location=str(log.relative_to(out)), raw={"log": str(log)}))
    for js in out.rglob("*.json"):
        d = read_json(js)
        if isinstance(d, dict) and d:
            res.append(f("sqlmap", t, category=Category.WEB_VULN, severity=Severity.HIGH,
                         id="sqli", title="sqlmap result", description=str(d)[:2000],
                         location=str(js.relative_to(out)), raw=d))
    return res
