from __future__ import annotations
from collections import Counter, defaultdict

_SEV = ["critical", "high", "medium", "low", "info", "unknown"]
# what each category fundamentally measures — comparisons only make sense within one
_CAT_LABEL = {
    "pkg-vuln": "CVEs in installed packages / dependencies",
    "secret": "embedded credentials / keys",
    "image-config": "image hardening / Dockerfile smells",
    "web-vuln": "web findings from DAST over HTTP",
    "network-vuln": "network-service vulns (e.g. OpenVAS NVTs)",
    "malware": "AV / YARA signature hits",
    "sbom-component": "inventory (not findings)",
    "other": "SAST / misc",
}


def _pctl(xs: list[float], q: float) -> float:
    if not xs:
        return 0.0
    xs = sorted(xs)
    return xs[min(len(xs) - 1, max(0, round(q * (len(xs) - 1))))]


def _fmt_t(s: float) -> str:
    return f"{s:.0f}s" if s < 60 else (f"{s / 60:.1f}m" if s < 3600 else f"{s / 3600:.1f}h")


def _bar(parts: dict, width: int = 24) -> str:
    tot = sum(parts.get(s, 0) for s in _SEV) or 1
    blocks = "█▓▒░·· "
    return "".join((blocks[i] if i < len(blocks) else "·") * round(parts.get(s, 0) / tot * width)
                   for i, s in enumerate(_SEV)) or "·"


def _category_agreement(findings: list[dict], category: str, scs: list[str], lines: list[str]) -> None:
    fs = [f for f in findings if f.get("category") == category]
    if not fs or len(scs) < 2:
        return
    lines += [f"### {category} — {len(scs)} scanners: {', '.join(scs)}", "",
              f"{len(fs)} merged {category} finding(s):", ""]
    agree = Counter(min(len(f.get("found_by") or []), 5) for f in fs)
    for k in sorted(agree):
        lines.append(f"- found by {k}{'+' if k == 5 else ''} scanner(s): **{agree[k]}** ({agree[k] / len(fs) * 100:.0f}%)")
    inter: dict = defaultdict(int); uni: dict = defaultdict(int)
    for f in fs:
        fb = set(f.get("found_by") or [])
        for i, a in enumerate(scs):
            for b in scs[i + 1:]:
                if a in fb or b in fb:
                    uni[(a, b)] += 1
                if a in fb and b in fb:
                    inter[(a, b)] += 1
    lines += ["", "Pairwise overlap (Jaccard):", "", "| | " + " | ".join(scs) + " |", "|---|" + "---|" * len(scs)]
    for a in scs:
        row = [a]
        for b in scs:
            if a == b:
                row.append("—"); continue
            key = (a, b) if (a, b) in uni else (b, a)
            row.append(f"{inter.get(key, 0) / uni[key]:.2f}" if uni.get(key) else "0.00")
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")


def analyze(corpus: dict, top: int = 20) -> str:
    summary = corpus.get("summary") or {}
    targets = corpus.get("targets") or []
    invocations = corpus.get("invocations") or []
    findings = corpus.get("findings") or []     # merged, with `found_by`
    L: list[str] = []

    # what each scanner actually produces — comparisons are per-category
    cat_scanners: dict[str, set] = defaultdict(set)
    scanner_cats: dict[str, set] = defaultdict(set)
    for f in findings:
        c = f.get("category", "other")
        for s in (f.get("found_by") or []):
            cat_scanners[c].add(s); scanner_cats[s].add(c)

    L += ["# Scanner battery — analysis", "",
          "_How to read this._ The scanners measure **different things** — some look for CVEs in "
          "installed packages, others for embedded secrets, image-hardening issues, malware signatures, "
          "or live web findings. So compare scanners **within a category**, never across: a TruffleHog "
          "secret \"missing\" from Trivy isn't a coverage gap — Trivy doesn't scan for secrets. Within a "
          "category, scanners still disagree by design (different vuln databases, dependency resolution, "
          "CVE↔package mappings), so low pairwise overlap and a tall \"found by 1 tool\" bar are expected. "
          "A finding seen by only one scanner *in a category others also cover* is a "
          "triage item / coverage signal, not automatically a false positive; one seen by 3+ independent "
          "scanners is the highest-confidence one. \"Most findings\" ≠ \"best scanner\" — extra findings are "
          "often duplication or over-broad CPE matching.", ""]

    # ── overview ────────────────────────────────────────────────────────────
    L += [f"- targets in corpus: **{summary.get('targets', len(targets))}** "
          f"(scanned: {summary.get('targets_scanned', '?')}, with container IP: {summary.get('targets_with_ip', '?')})",
          f"- scanners that produced data: **{summary.get('scanners', '?')}**  ·  merged findings: **{len(findings)}**", ""]
    by_sev = summary.get("findings_by_severity") or Counter(f["severity"] for f in findings)
    by_cat = summary.get("findings_by_category") or Counter(f["category"] for f in findings)
    L += ["**What was measured** (category → scanners that produced findings in it):", ""]
    for c in sorted(cat_scanners, key=lambda c: -by_cat.get(c, 0)):
        L.append(f"- `{c}` — {_CAT_LABEL.get(c, c)} — {by_cat.get(c, 0)} findings, "
                 f"by: {', '.join(sorted(cat_scanners[c]))}")
    L.append("")
    L += ["| severity | count |", "|---|---:|"]
    for sev in [s for s in _SEV if by_sev.get(s)]:
        L.append(f"| {sev} | {by_sev.get(sev, 0)} |")
    L.append("")

    # ── throughput ──────────────────────────────────────────────────────────
    tp = summary.get("throughput") or {}
    if tp:
        L += ["## Throughput", "",
              f"- wall clock: **{_fmt_t(tp.get('wall_clock_seconds', 0))}** "
              f"for {summary.get('targets_scanned', '?')} containers",
              f"- **{tp.get('targets_per_hour', 0):.1f} containers / hour** ({tp.get('targets_per_minute', 0):.2f} / min)",
              f"- per container: avg {_fmt_t(tp.get('avg_seconds_per_target', 0))}, "
              f"median {_fmt_t(tp.get('median_seconds_per_target', 0))}",
              f"- scanner-CPU time: {_fmt_t(tp.get('scanner_cpu_seconds_total', 0))} total → "
              f"parallel efficiency ≈ **{tp.get('parallel_efficiency', 0):.1f}×** (avg concurrent scanner containers)", ""]

    # ── per-scanner ─────────────────────────────────────────────────────────
    by_scanner: dict[str, dict] = defaultdict(lambda: {"runs": 0, "status": Counter(), "wall": [], "mem": 0.0})
    for inv in invocations:
        b = by_scanner[inv["scanner"]]
        b["runs"] += 1
        b["status"][inv.get("status", "?")] += 1
        try:
            b["wall"].append(float(inv.get("wall_seconds") or 0))
        except (TypeError, ValueError):
            pass
        b["mem"] = max(b["mem"], float(inv.get("peak_mem_mb") or 0))
    merged_by_scanner = Counter(s for f in findings for s in (f.get("found_by") or []))
    # "exclusive" only counts when another scanner *also covers that category* but missed it
    excl_meaningful: Counter = Counter()
    excl_total: Counter = Counter()
    for f in findings:
        fb = f.get("found_by") or []
        if len(fb) == 1:
            s = fb[0]; c = f.get("category", "other")
            excl_total[s] += 1
            if len(cat_scanners.get(c, ())) > 1:
                excl_meaningful[s] += 1

    L += ["## Per-scanner", "",
          "| scanner | categories | runs | ok | err | timeout | skip | avg | p50 | p95 | peak mem | findings | exclusive |",
          "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for s in sorted(by_scanner, key=lambda s: -merged_by_scanner.get(s, 0)):
        b = by_scanner[s]; st = b["status"]; w = b["wall"]
        ok = st.get("ok", 0) + st.get("nonzero-ok", 0) + st.get("ok-cached", 0)
        cats = ",".join(sorted(scanner_cats.get(s, ()))) or "—"
        sole = all(len(cat_scanners.get(c, ())) <= 1 for c in scanner_cats.get(s, ()))
        ex = f"{excl_meaningful.get(s, 0)} ({excl_total.get(s, 0)})" if not sole else f"(sole · {excl_total.get(s, 0)})"
        L.append(f"| {s} | {cats} | {b['runs']} | {ok} | {st.get('error', 0)} | {st.get('timeout', 0)} | "
                 f"{st.get('skipped', 0)} | {_fmt_t(sum(w) / len(w)) if w else '—'} | {_fmt_t(_pctl(w, 0.5))} | "
                 f"{_fmt_t(_pctl(w, 0.95))} | {b['mem']:.0f}MB | {merged_by_scanner.get(s, 0)} | {ex} |")
    L += ["", "`exclusive` = findings only this scanner reported, *and* another scanner covering the same "
          "category was running too (so it's a real divergence); `(N)` = its total solo findings. "
          "`(sole · N)` means it's the only scanner of its category here — its N solo findings just reflect "
          "that no comparable tool ran.", ""]

    # ── within-category agreement ───────────────────────────────────────────
    cmp_cats = [c for c in cat_scanners if len(cat_scanners[c]) >= 2 and c != "sbom-component"]
    if cmp_cats:
        L += ["## Within-category agreement", ""]
        for c in sorted(cmp_cats, key=lambda c: -by_cat.get(c, 0)):
            _category_agreement(findings, c, sorted(cat_scanners[c]), L)

    # ── severity × category ─────────────────────────────────────────────────
    sxc: dict = Counter((f.get("severity", "unknown"), f.get("category", "other")) for f in findings)
    allcats = sorted({c for _, c in sxc})
    if findings:
        L += ["## Severity × category", "", "| severity | " + " | ".join(allcats) + " | total |",
              "|---|" + "---:|" * (len(allcats) + 1)]
        for sev in [s for s in _SEV if by_sev.get(s)]:
            L.append("| " + " | ".join([sev] + [str(sxc.get((sev, c), 0)) for c in allcats]
                                       + [str(by_sev.get(sev, 0))]) + " |")
        L.append("")

    # ── most exposed containers ─────────────────────────────────────────────
    per_t_sev: dict = defaultdict(Counter); per_t_ip: dict = {}
    for f in findings:
        per_t_sev[f.get("target_name", "?")][f.get("severity", "unknown")] += 1
        if f.get("target_ip"):
            per_t_ip.setdefault(f["target_name"], f["target_ip"])
    for t in targets:
        if t.get("container_ip") and t.get("name"):
            per_t_ip.setdefault(t["name"], t["container_ip"])
    ranked = sorted(per_t_sev.items(), key=lambda kv: -sum(kv[1].values()))[:top]
    if ranked:
        L += [f"## Most exposed containers (top {len(ranked)})", "",
              "| container | ip | findings | crit | high | med | low | severity |",
              "|---|---|---:|---:|---:|---:|---:|---|"]
        for name, sv in ranked:
            L.append(f"| {name} | {per_t_ip.get(name, '')} | {sum(sv.values())} | {sv.get('critical', 0)} | "
                     f"{sv.get('high', 0)} | {sv.get('medium', 0)} | {sv.get('low', 0)} | `{_bar(sv)}` |")
        L.append("")

    return "\n".join(L)
