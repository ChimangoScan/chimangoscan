from __future__ import annotations
import re
from pathlib import Path

from ..models import Category, Severity, Target
from .base import f

# `clamscan -r -i` prints "<path>: <signature> FOUND" per infected file.
_HIT = re.compile(r"^(.*?): (.+?) FOUND\s*$")


def parse(out: Path, t: Target) -> list[Finding]:
    txt = next(out.glob("*.clamav.txt"), None)
    if not txt or not txt.is_file():
        return []
    res = []
    for line in txt.read_text(errors="replace").splitlines():
        m = _HIT.match(line)
        if not m:
            continue
        path, sig = m.group(1), m.group(2)
        loc = path[6:] if path.startswith("/scan/") else path
        res.append(f("clamav", t, category=Category.MALWARE, severity=Severity.HIGH,
                     id=sig, title=sig, description=f"ClamAV signature {sig}",
                     location=loc, raw={"signature": sig, "path": loc}))
    return res
