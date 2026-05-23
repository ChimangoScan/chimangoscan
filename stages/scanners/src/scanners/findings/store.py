from __future__ import annotations
import csv, json
from collections import Counter
from pathlib import Path
from typing import Iterable

from ..models import Finding, Target, TargetReport
from .merge import dedup

_CORPUS = "_corpus"
_METRIC_FIELDS = ["target_name", "target_image", "target_ip", "scanner", "mode", "image_ref",
                  "status", "exit_code", "wall_seconds", "peak_cpu_pct", "peak_mem_mb",
                  "stdout_bytes", "stderr_bytes", "output_bytes", "findings", "error"]


class TargetStore:
    """`out/<slug>/` — one directory per target; raw scanner artifacts kept verbatim."""

    def __init__(self, out_dir: Path, target: Target):
        self.root = out_dir / target.name
        self.root.mkdir(parents=True, exist_ok=True)

    def scanner_dir(self, scanner: str) -> Path:
        d = self.root / scanner
        d.mkdir(parents=True, exist_ok=True)
        return d

    def write_artifacts(self, scanner: str, *, stdout: bytes = b"", stderr: bytes = b"",
                        cmd: list[str] | None = None, exit_code: int | None = None,
                        failed: bool = False) -> None:
        """Persist raw scanner artifacts under `<slug>/<scanner>/`.
        - `output.json` keeps stdout when the scanner didn't already write a captured file.
        - On failure also drops `error.log`, `cmd.log` and `exit_code` for forensics."""
        d = self.scanner_dir(scanner)
        if stdout:
            (d / "output.json").write_bytes(stdout)
        if failed:
            (d / "error.log").write_bytes(stderr or b"")
            (d / "cmd.log").write_text(" ".join(cmd or []) + "\n")
            (d / "exit_code").write_text(f"{exit_code if exit_code is not None else ''}\n")

    def write_report(self, report: TargetReport) -> None:
        # compact (no indent) — at scale these add up; the raw artifacts next to it are the readable record
        (self.root / "report.json").write_text(json.dumps(report.to_json(), separators=(",", ":")))


class CorpusStore:
    """`out/_corpus/` — the aggregates the HTML report is built from. Rebuilt
    wholesale from a stream of per-target reports (queue or on-disk)."""

    def __init__(self, out_dir: Path):
        self.root = out_dir / _CORPUS
        self.root.mkdir(parents=True, exist_ok=True)

    def rebuild(self, reports: Iterable[dict], extra_findings: Iterable[Finding] = ()) -> dict:
        findings: list[Finding] = list(extra_findings)
        invocations: list[dict] = []
        targets: list[dict] = []
        for r in reports:
            tgt = r.get("target") or {}
            targets.append({**tgt, "container_ip": r.get("container_ip"),
                            "open_ports": r.get("open_ports") or [],
                            "n_findings": len(r.get("findings") or []),
                            "started_at": r.get("started_at", ""), "finished_at": r.get("finished_at", ""),
                            "skipped_reason": r.get("skipped_reason", "")})
            for inv in r.get("invocations") or []:
                invocations.append(inv)
            for fd in r.get("findings") or []:
                fd.pop("raw", None)               # corpus view doesn't need the raw records; keep memory bounded
                findings.append(Finding.from_json(fd))
            r["findings"] = None                  # let the just-processed report be GC'd
        merged = dedup(findings)

        (self.root / "findings.jsonl").write_text("".join(json.dumps(m) + "\n" for m in merged))
        with (self.root / "metrics.csv").open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=_METRIC_FIELDS, extrasaction="ignore")
            w.writeheader()
            for inv in invocations:
                w.writerow(inv)
        (self.root / "targets.jsonl").write_text("".join(json.dumps(t) + "\n" for t in targets))

        summary = _summarize(targets, invocations, merged)
        (self.root / "summary.json").write_text(json.dumps(summary, indent=2))
        return {"summary": summary, "targets": targets, "invocations": invocations, "findings": merged}

    def load(self) -> dict | None:
        s = self.root / "summary.json"
        if not s.is_file():
            return None
        merged = [json.loads(l) for l in (self.root / "findings.jsonl").read_text().splitlines() if l.strip()]
        targets = [json.loads(l) for l in (self.root / "targets.jsonl").read_text().splitlines() if l.strip()]
        with (self.root / "metrics.csv").open(newline="") as fh:
            invocations = list(csv.DictReader(fh))
        return {"summary": json.loads(s.read_text()), "targets": targets,
                "invocations": invocations, "findings": merged}


def _summarize(targets: list[dict], invocations: list[dict], merged: list[dict]) -> dict:
    by_sev = Counter(m["severity"] for m in merged)
    by_cat = Counter(m["category"] for m in merged)
    by_scanner_findings = Counter()
    for m in merged:
        for s in m.get("found_by") or []:
            by_scanner_findings[s] += 1
    inv_by_scanner: dict[str, dict] = {}
    for inv in invocations:
        s = inv["scanner"]
        b = inv_by_scanner.setdefault(s, {"runs": 0, "ok": 0, "wall": 0.0, "mem": 0.0, "findings": 0})
        b["runs"] += 1
        b["ok"] += 1 if str(inv.get("status", "")).startswith("ok") or inv.get("status") == "nonzero-ok" else 0
        b["wall"] += float(inv.get("wall_seconds") or 0)
        b["mem"] = max(b["mem"], float(inv.get("peak_mem_mb") or 0))
        b["findings"] += int(inv.get("findings") or 0)
    scanners = {}
    for s, b in inv_by_scanner.items():
        scanners[s] = {"runs": b["runs"], "ok": b["ok"],
                       "avg_wall_s": round(b["wall"] / b["runs"], 1) if b["runs"] else 0.0,
                       "peak_mem_mb": round(b["mem"], 1), "raw_findings": b["findings"],
                       "merged_findings": by_scanner_findings.get(s, 0)}
    # cross-scanner agreement on package CVEs
    pkg = [m for m in merged if m["category"] == "pkg-vuln"]
    agreement = Counter(min(m["n_scanners"], 4) for m in pkg)
    return {
        "targets": len(targets),
        "targets_scanned": sum(1 for t in targets if not t.get("skipped_reason")),
        "scanners": len(scanners),
        "findings_merged": len(merged),
        "findings_by_severity": dict(by_sev),
        "findings_by_category": dict(by_cat),
        "scanner_stats": scanners,
        "pkg_vuln_agreement": {str(k): v for k, v in sorted(agreement.items())},
        "targets_with_ip": sum(1 for t in targets if t.get("container_ip") or t.get("ip")),
        "throughput": _throughput(targets, invocations),
    }


def _throughput(targets: list[dict], invocations: list[dict]) -> dict:
    import datetime as _dt
    def _ts(x):
        try:
            return _dt.datetime.strptime(x, "%Y-%m-%dT%H:%M:%SZ")
        except (TypeError, ValueError):
            return None
    starts = [t for t in (_ts(x.get("started_at")) for x in targets) if t]
    ends = [t for t in (_ts(x.get("finished_at")) for x in targets) if t]
    if not starts or not ends:
        return {}
    span = max((max(ends) - min(starts)).total_seconds(), 1e-9)
    scanned = sum(1 for t in targets if not t.get("skipped_reason"))
    per_target = [(_te - _ts_) .total_seconds() for _ts_, _te in
                  ((_ts(t.get("started_at")), _ts(t.get("finished_at"))) for t in targets) if _ts_ and _te and _te >= _ts_]
    cpu_seconds = sum(float(i.get("wall_seconds") or 0) for i in invocations)
    return {
        "wall_clock_seconds": round(span, 1),
        "targets_per_minute": round(scanned / span * 60, 3),
        "targets_per_hour": round(scanned / span * 3600, 1),
        "avg_seconds_per_target": round(sum(per_target) / len(per_target), 1) if per_target else 0.0,
        "median_seconds_per_target": round(sorted(per_target)[len(per_target) // 2], 1) if per_target else 0.0,
        "scanner_cpu_seconds_total": round(cpu_seconds, 1),
        "parallel_efficiency": round(cpu_seconds / span, 2),   # ≈ avg concurrent scanner containers
    }
