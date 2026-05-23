from __future__ import annotations
import re
from pathlib import Path

from ..models import Category, Finding, Severity, Target
from .base import cves_in, f, read_json


# CVSS v3 base-score formula (FIRST.org spec §7.1). OSV stores the vector as a
# string (e.g. "CVSS:3.1/AV:N/AC:L/...") with no numeric tail, so the previous
# trailing-digit regex always failed and every finding fell back to UNKNOWN.
_V3_M = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {  # scope-dependent; tuple = (unchanged, changed)
        "N": (0.85, 0.85), "L": (0.62, 0.68), "H": (0.27, 0.50),
    },
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
# CVSS v4 base-score is much more involved; do a coarse lookup on the
# exploitability/impact metrics instead of pulling in a dependency.
_V4_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    # CVSS v3.1 "Round up to 1 decimal place".
    return -(-x * 10 // 1) / 10


def _cvss_v3_score(vec: str) -> float | None:
    parts = dict(p.split(":", 1) for p in vec.split("/")[1:] if ":" in p)
    try:
        scope_changed = parts.get("S") == "C"
        av = _V3_M["AV"][parts["AV"]]; ac = _V3_M["AC"][parts["AC"]]
        pr = _V3_M["PR"][parts["PR"]][1 if scope_changed else 0]
        ui = _V3_M["UI"][parts["UI"]]
        c = _V3_M["C"][parts["C"]]; i = _V3_M["I"][parts["I"]]; a = _V3_M["A"][parts["A"]]
    except KeyError:
        return None
    isc_base = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15 if scope_changed \
        else 6.42 * isc_base
    if impact <= 0:
        return 0.0
    expl = 8.22 * av * ac * pr * ui
    raw = min((1.08 * (impact + expl)) if scope_changed else (impact + expl), 10.0)
    return _roundup(raw)


def _cvss_v4_score(vec: str) -> float | None:
    # Coarse estimate: max of impact metrics × exploit-friendliness. Enough to
    # bucket into critical/high/medium/low; precise scoring would need the full
    # CVSS v4 lookup tables.
    parts = dict(p.split(":", 1) for p in vec.split("/")[1:] if ":" in p)
    try:
        impact = max(_V4_IMPACT[parts["VC"]], _V4_IMPACT[parts["VI"]], _V4_IMPACT[parts["VA"]])
    except KeyError:
        return None
    if impact == 0:
        return 0.0
    av_bonus = {"N": 1.0, "A": 0.85, "L": 0.7, "P": 0.5}.get(parts.get("AV", "N"), 0.7)
    ac_bonus = {"L": 1.0, "H": 0.75}.get(parts.get("AC", "L"), 0.85)
    return round(min(10.0, impact * av_bonus * ac_bonus * 17.5), 1)


def _cvss(v: dict) -> float | None:
    """Best numeric CVSS score across all severity[] entries."""
    best = None
    for s in v.get("severity") or []:
        kind = str(s.get("type", "")).upper()
        score_str = str(s.get("score", ""))
        if not score_str:
            continue
        n = None
        if score_str.startswith("CVSS:3"):
            n = _cvss_v3_score(score_str)
        elif score_str.startswith("CVSS:4"):
            n = _cvss_v4_score(score_str)
        elif kind.startswith("CVSS"):
            # Some sources put a bare numeric here.
            m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*", score_str)
            if m:
                n = float(m.group(1))
        if n is not None:
            best = max(best or 0.0, n)
    return best


def _qual_severity(v: dict) -> Severity:
    """Fallback when no parseable CVSS vector is present.

    OSV ecosystems (GHSA, etc.) commonly omit `severity[]` entirely but expose
    a qualitative bucket via `database_specific.severity`.
    """
    db = v.get("database_specific")
    if isinstance(db, dict) and db.get("severity"):
        return Severity.parse(db["severity"])
    # A few feeds use a non-CVSS string in severity[].score (e.g. "HIGH").
    for s in v.get("severity") or []:
        score_str = str(s.get("score", ""))
        if score_str and not score_str.upper().startswith("CVSS:"):
            sev = Severity.parse(score_str)
            if sev is not Severity.UNKNOWN:
                return sev
    return Severity.UNKNOWN


def parse(out: Path, t: Target) -> list[Finding]:
    doc = read_json(out / f"{t.name}.osv.json")
    if not isinstance(doc, dict):
        return []
    res: list[Finding] = []
    for r in doc.get("results") or []:
        src = (r.get("source") or {}).get("path", "")
        for pkg in r.get("packages") or []:
            p = pkg.get("package") or {}
            for v in pkg.get("vulnerabilities") or []:
                aliases = v.get("aliases") or []
                vid = next((a for a in aliases if str(a).upper().startswith("CVE")), v.get("id", ""))
                score = _cvss(v)
                severity = Severity.from_cvss(score) if score is not None else _qual_severity(v)
                res.append(f("osv", t, category=Category.PKG_VULN,
                             severity=severity,
                             id=vid, title=(v.get("summary") or vid)[:200],
                             description=(v.get("details") or "")[:1000], cvss=score,
                             package=p.get("name", ""), version=p.get("version", ""),
                             ecosystem=p.get("ecosystem", ""), location=src,
                             cves=[a for a in aliases if str(a).upper().startswith("CVE")] or cves_in(vid),
                             references=[x.get("url") for x in (v.get("references") or []) if x.get("url")][:10],
                             raw=v))
    return res
