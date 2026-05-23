from __future__ import annotations
import re
from pathlib import Path

from ..models import Category, Severity, Target
from .base import f

# `yara -r -s rules dir` prints "<rule> <path>" per match; with -s, indented
# lines below list the matched strings (offset:identifier:value). We keep those.
_MATCH = re.compile(r"^(\S+)\s+(/scan/\S.*)$")
_STR = re.compile(r"^0x[0-9a-f]+:\$")


def parse(out: Path, t: Target) -> list[Finding]:
    txt = next(out.glob("*.yara.txt"), None)
    if not txt or not txt.is_file():
        return []
    res, cur, strings = [], None, []
    for line in txt.read_text(errors="replace").splitlines():
        m = _MATCH.match(line)
        if m:
            if cur:
                res.append(_finding(t, cur[0], cur[1], strings))
            cur, strings = (m.group(1), m.group(2)), []
        elif cur and (line.startswith("0x") or _STR.match(line)):
            strings.append(line.strip())
    if cur:
        res.append(_finding(t, cur[0], cur[1], strings))
    return res


def _finding(t: Target, rule: str, path: str, strings: list[str]) -> Finding:
    loc = path[6:] if path.startswith("/scan/") else path
    return f("yara", t, category=Category.MALWARE, severity=Severity.MEDIUM,
             id=rule, title=f"YARA rule {rule}",
             description=("; ".join(strings[:8]))[:600] if strings else "",
             location=loc, raw={"rule": rule, "path": loc, "matched_strings": strings[:30]})
