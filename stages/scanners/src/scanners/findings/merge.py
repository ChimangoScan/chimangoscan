from __future__ import annotations
from collections import defaultdict
from typing import Iterable

from ..models import Finding, Severity

_SEV_RANK = {Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3,
             Severity.LOW: 2, Severity.INFO: 1, Severity.UNKNOWN: 0}


def worst(a: Severity, b: Severity) -> Severity:
    return a if _SEV_RANK[a] >= _SEV_RANK[b] else b


def dedup(findings: Iterable[Finding]) -> list[dict]:
    """Collapse identical findings reported by several scanners into one record
    that carries `found_by` (which scanners saw it). Keyed within a target."""
    groups: dict[tuple, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[(f.target_name, f.merge_key())].append(f)

    out: list[dict] = []
    for (_target, _key), members in groups.items():
        rep = max(members, key=lambda m: (_SEV_RANK[m.severity], m.cvss or 0.0))
        sev = rep.severity
        for m in members:
            sev = worst(sev, m.severity)
        cves = sorted({c.upper() for m in members for c in m.cves})
        refs = sorted({r for m in members for r in m.references if r})
        cvss = max((m.cvss for m in members if m.cvss is not None), default=None)
        out.append({
            **rep.to_json(),
            "severity": sev.value,
            "cvss": cvss,
            "cves": cves,
            "references": refs,
            # provenance: take the first non-empty value across members
            "target_ip": next((m.target_ip for m in members if m.target_ip), rep.target_ip),
            "endpoint": next((m.endpoint for m in members if m.endpoint), rep.endpoint),
            "fixed_version": next((m.fixed_version for m in members if m.fixed_version), rep.fixed_version),
            "found_by": sorted({m.scanner for m in members}),
            "n_scanners": len({m.scanner for m in members}),
        })
        out[-1].pop("raw", None)   # the merged corpus view doesn't carry the bulky raw records
    out.sort(key=lambda d: (-_SEV_RANK[Severity(d["severity"])], -(d["cvss"] or 0.0),
                            d["target_name"], d["id"]))
    return out
