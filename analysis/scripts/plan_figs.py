#!/usr/bin/env python3
"""
Figures for the analysis plan (Parts A and B). Publication style shared with
the rest of the paper (figstyle.py). Output in figures/.

  fig_pull_vs_vuln.pdf   A-fig-1 + N4: (a) pull count vs vulnerabilities
                         scatter (Shu 2017 negative result re-tested),
                         (b) vulnerabilities by exposure decile.
  fig_allvsdistinct.pdf  A-fig-2: all findings vs distinct (cve,pkg) groups
                         by severity (Wist 2021 Fig. 2).
  fig_secret_cdf.pdf     A-fig-3: CDF of secrets per image, official vs
                         community (Dahlmanns 2023).
  fig_crawl_cdf.pdf      A-fig-4/5: CDFs of repository pull count and image
                         dependency weight (Dr. Docker Fig. 2-4).
  fig_marginal_scanner.pdf  N1: marginal coverage of the Nth scanner.
"""
import json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
from matplotlib.patches import Circle
import numpy as np
import figstyle

OUT = "."
figstyle.apply()
PL = json.load(open(os.path.join(OUT, "plan_analysis.json")))


def save(fig, base, dpi=300):
    os.makedirs(os.path.join(OUT, "figures"), exist_ok=True)
    fig.savefig(os.path.join(OUT, "figures", base + ".pdf"),
                bbox_inches="tight", pad_inches=0.03, dpi=dpi)
    plt.close(fig)
    print("wrote figures/" + base + ".pdf")


def mil(x, _p=None):
    a = abs(x)
    if a >= 1e9:
        return f"{x/1e9:.0f}B"
    if a >= 1e6:
        return f"{x/1e6:.0f}M"
    if a >= 1e3:
        return f"{x/1e3:.0f}k"
    return f"{x:.0f}"
mfmt = FuncFormatter(mil)
SEV_COLORS = {"critical": "#7a0177", "high": "#d7301f", "medium": "#fc8d59",
              "low": "#fee08b", "info": "#91bfdb", "unknown": "#bdbdbd"}


# ============================================================
# A-fig-1 + N4: pull count vs vulnerabilities, and exposure deciles
# ============================================================
def fig_pull_vs_vuln():
    sd = json.load(open(os.path.join(OUT, "plan_scatter.json")))
    pull = np.array(sd["pull"], dtype=float)
    vuln = np.array(sd["vuln"], dtype=float)
    expo = np.array(sd["exposure"], dtype=float)
    n4 = PL["afig1_n4"]

    fig, ax = plt.subplots(1, 2, figsize=(7.0, 2.3))

    # (a) pull vs vulnerabilities, log-log. The image cloud is dense (tens of
    # thousands of points), so it is drawn as a 2-D hexbin density map rather
    # than an overplotted scatter: lighter file, no visual clutter, same
    # message (no pull-count/vulnerability relationship). The hexbin patches
    # are rasterized so the PDF stays small; axes/labels remain vector.
    m = (pull > 0) & (vuln > 0)
    lx = np.log10(pull[m])
    ly = np.log10(vuln[m])
    hb = ax[0].hexbin(lx, ly, gridsize=34, cmap="Blues", mincnt=1,
                      linewidths=0.0, bins="log", rasterized=True, zorder=2)
    cb = fig.colorbar(hb, ax=ax[0], pad=0.02, fraction=0.046)
    cb.set_label("Images per bin", fontsize=6.6)
    cb.ax.tick_params(labelsize=6.0)
    cb.outline.set_linewidth(0.6)

    def _logfmt(v, _p=None):
        return mil(10 ** v)
    ax[0].xaxis.set_major_formatter(FuncFormatter(_logfmt))
    ax[0].yaxis.set_major_formatter(FuncFormatter(_logfmt))
    ax[0].set_xlabel("Repository pull count")
    ax[0].set_ylabel("Distinct vulnerabilities per image")
    figstyle.grid(ax[0], "both")
    rho = n4["rho_pull_vs_vuln"]
    ax[0].text(0.04, 0.94, f"Spearman $\\rho={rho:+.3f}$", transform=ax[0].transAxes,
               fontsize=8, va="top",
               bbox=dict(boxstyle="round,pad=0.25", fc="white", ec="#bbb", lw=0.6))
    ax[0].set_title("(a) pull count")

    # (b) vulnerabilities by exposure decile (median + IQR band) + crit prev
    dec = n4["exposure_deciles"]
    xs = [d["decile"] for d in dec]
    med = [d["median_vuln"] for d in dec]
    q1 = [d["q1_vuln"] for d in dec]
    q3 = [d["q3_vuln"] for d in dec]
    crit = [d["critical_prevalence_pct"] for d in dec]
    figstyle.grid(ax[1], "y")
    ax[1].fill_between(xs, q1, q3, color="#2166ac", alpha=0.18, zorder=2,
                       label="IQR")
    ax[1].plot(xs, med, "o-", color="#2166ac", markersize=3.6, zorder=4,
               label="median vuln.")
    ax[1].set_xlabel("Exposure decile (1 = lowest)")
    ax[1].set_ylabel("Distinct vulnerabilities per image")
    ax[1].set_xticks(range(1, 11))
    ax[1].set_ylim(bottom=0)
    axr = ax[1].twinx()
    axr.spines["top"].set_visible(False)
    axr.plot(xs, crit, "s--", color="#d7301f", markersize=3.0, zorder=4,
             label="critical prev.")
    axr.set_ylabel("Images with a critical vuln. (%)", color="#d7301f")
    axr.tick_params(axis="y", colors="#d7301f")
    axr.set_ylim(0, 105)
    rhoe = n4["rho_exposure_vs_vuln"]
    ax[1].set_title(f"(b) exposure decile ($\\rho={rhoe:+.3f}$)")
    h1, l1 = ax[1].get_legend_handles_labels()
    h2, l2 = axr.get_legend_handles_labels()
    # the data fills the top of the panel (critical prevalence near 100%),
    # so the legend goes lower-left where the median curve leaves room.
    ax[1].legend(h1 + h2, l1 + l2, loc="lower left", fontsize=6.6,
                 borderpad=0.3, labelspacing=0.3)
    fig.tight_layout(w_pad=2.4)
    save(fig, "fig_pull_vs_vuln", dpi=200)


# ============================================================
# A-fig-2: all findings vs distinct groups by severity
# ============================================================
def fig_allvsdistinct():
    a = PL["afig2_ctab4"]
    sev_all = a["sev_all_findings"]
    sev_dist = a["sev_distinct_groups"]
    order = ["critical", "high", "medium", "low", "info", "unknown"]
    order = [s for s in order if sev_all.get(s, 0) or sev_dist.get(s, 0)]
    labels = {"critical": "Critical", "high": "High", "medium": "Medium",
              "low": "Low", "info": "Info", "unknown": "Unrated"}
    allv = [sev_all.get(s, 0) for s in order]
    dstv = [sev_dist.get(s, 0) for s in order]

    fig, ax = plt.subplots(figsize=(3.5, 2.6))
    figstyle.grid(ax, "y")
    x = np.arange(len(order))
    bw = 0.38
    ax.bar(x - bw / 2, allv, bw, color="#4575b4", label="all findings",
           edgecolor="white", linewidth=0.4, zorder=3)
    ax.bar(x + bw / 2, dstv, bw, color="#d73027", label="distinct (CVE, pkg)",
           edgecolor="white", linewidth=0.4, zorder=3)
    ax.set_xticks(x)
    ax.set_xticklabels([labels[s] for s in order], rotation=25, ha="right")
    ax.set_ylabel("Vulnerability count")
    ax.yaxis.set_major_formatter(mfmt)
    ax.set_yscale("log")
    ax.legend(loc="upper right", fontsize=7)
    ax.margins(y=0.18)
    save(fig, "fig_allvsdistinct")


# ============================================================
# A-fig-3: CDF of secrets per image, official vs community
# ============================================================
def fig_secret_cdf():
    sd = json.load(open(os.path.join(OUT, "plan_scatter.json")))
    off = np.array(sorted(sd["sec_off"]), dtype=float)
    com = np.array(sorted(sd["sec_com"]), dtype=float)
    # low, wide panel: it sits beside Table 8 (Dockle misconfiguration) in a
    # side-by-side minipage, so it is kept short to save vertical space.
    fig, ax = plt.subplots(figsize=(3.5, 1.55))
    figstyle.grid(ax, "both")
    for arr, col, lab in ((com, "#cb6a3e", "Community"),
                          (off, "#2c7fb8", "Official")):
        a = arr.copy()
        a[a < 1] = 0.7   # place zero-secret images at the left edge on log x
        y = np.arange(1, len(a) + 1) / len(a)
        ax.step(np.sort(a), y, where="post", color=col, label=lab)
    ax.set_xscale("log")
    ax.set_xlabel("TruffleHog secret detections per image")
    ax.set_ylabel("Cumulative fraction")
    ax.set_ylim(0, 1.02)
    ax.legend(loc="lower right", fontsize=7.4)
    save(fig, "fig_secret_cdf")


# ============================================================
# A-fig-4 / A-fig-5: CDFs of repository pull count and dependency weight
# ============================================================
def fig_crawl_cdf():
    cd = json.load(open(os.path.join(OUT, "plan_crawl.json")))
    fig, ax = plt.subplots(1, 2, figsize=(7.0, 2.6))

    pull = np.array(sorted(cd["pull"]), dtype=float)
    p = pull.copy()
    p[p < 1] = 0.7
    y = np.arange(1, len(p) + 1) / len(p)
    figstyle.grid(ax[0], "both")
    ax[0].step(np.sort(p), y, where="post", color="#2166ac")
    ax[0].set_xscale("log")
    ax[0].set_xlabel("Repository pull count")
    ax[0].set_ylabel("Cumulative fraction of repositories")
    ax[0].set_ylim(0, 1.02)
    ax[0].set_title("(a) pull count")

    dw = np.array(sorted(cd["depweight_base"]), dtype=float)
    y2 = np.arange(1, len(dw) + 1) / len(dw)
    figstyle.grid(ax[1], "both")
    ax[1].step(dw, y2, where="post", color="#1a9850")
    ax[1].set_xscale("log")
    ax[1].set_xlabel("Dependency weight (downstream images)")
    ax[1].set_ylabel("Cumulative fraction of base images")
    ax[1].set_ylim(0, 1.02)
    ax[1].set_title("(b) dependency weight (base images)")
    fig.tight_layout(w_pad=2.2)
    save(fig, "fig_crawl_cdf")


# ============================================================
# N1: marginal coverage of the Nth vulnerability scanner
# ============================================================
def fig_marginal_scanner():
    n1 = PL["n1"]
    tot = n1["total_distinct_groups"]
    marg = n1["marginal_avg_pct"]
    cum = np.cumsum(marg)
    fig, ax = plt.subplots(figsize=(3.4, 2.5))
    figstyle.grid(ax, "y")
    xs = [1, 2, 3]
    ax.bar(xs, marg, width=0.55, color="#4575b4", edgecolor="white",
           linewidth=0.5, zorder=3, label="marginal gain")
    ax.plot(xs, cum, "o-", color="#d7301f", markersize=4.2, zorder=4,
            label="cumulative coverage")
    for x, c in zip(xs, cum):
        ax.text(x, c + 3, f"{c:.0f}%", ha="center", fontsize=7.2,
                color="#d7301f")
    ax.set_xticks(xs)
    ax.set_xlabel("Number of vulnerability scanners")
    ax.set_ylabel("Distinct vulnerabilities recovered (%)")
    ax.set_ylim(0, 116)
    ax.legend(loc="center right", fontsize=7, bbox_to_anchor=(1.0, 0.42))
    save(fig, "fig_marginal_scanner")


# ============================================================
# Inter-scanner divergence: three small panels grouped side by side
# (a) Venn-3 agreement, (b) marginal Nth-scanner coverage,
# (c) all findings vs distinct groups by severity.
# Replaces the three isolated figures fig_venn / fig_marginal_scanner /
# fig_allvsdistinct to use vertical space efficiently.
# ============================================================
def fig_panel_divergence():
    fig, ax = plt.subplots(1, 3, figsize=(7.0, 2.05))

    # ---- (a) Venn-3: Trivy / Grype / OSV ----
    ex = json.load(open(os.path.join(OUT, "extra_analysis.json")))
    v = ex["venn"]

    def m(x):
        return f"{x/1e6:.1f}M"
    a0 = ax[0]
    r = 1.0
    c = {"T": (-0.42, 0.30), "G": (0.42, 0.30), "O": (0.0, -0.42)}
    cols = {"T": "#4575b4", "G": "#d73027", "O": "#1a9850"}
    for k, (x, y) in c.items():
        a0.add_patch(Circle((x, y), r, alpha=0.32, facecolor=cols[k],
                            edgecolor=cols[k], linewidth=1.0))
    a0.text(-0.95, 0.95, m(v["trivy_only"]), ha="center", fontsize=7)
    a0.text(0.95, 0.95, m(v["grype_only"]), ha="center", fontsize=7)
    a0.text(0.0, -1.18, m(v["osv_only"]), ha="center", fontsize=7)
    a0.text(0.0, 0.66, m(v["trivy_grype"]), ha="center", fontsize=7)
    a0.text(-0.62, -0.32, m(v["trivy_osv"]), ha="center", fontsize=6.5)
    a0.text(0.62, -0.32, m(v["grype_osv"]), ha="center", fontsize=6.5)
    a0.text(0.0, 0.05, m(v["all3"]), ha="center", fontsize=7,
            fontweight="bold")
    a0.text(-1.05, 1.30, "Trivy", color=cols["T"], fontsize=8,
            fontweight="bold")
    a0.text(0.72, 1.30, "Grype", color=cols["G"], fontsize=8,
            fontweight="bold")
    a0.text(0.0, -1.62, "OSV-Scanner", color=cols["O"], ha="center",
            fontsize=8, fontweight="bold")
    a0.set_xlim(-2.0, 2.0)
    a0.set_ylim(-1.9, 1.6)
    a0.set_aspect("equal")
    a0.axis("off")
    a0.set_title("(a) scanner agreement")

    # ---- (b) marginal coverage of the Nth scanner ----
    n1 = PL["n1"]
    marg = n1["marginal_avg_pct"]
    cum = np.cumsum(marg)
    a1 = ax[1]
    figstyle.grid(a1, "y")
    xs = [1, 2, 3]
    a1.bar(xs, marg, width=0.55, color="#4575b4", edgecolor="white",
           linewidth=0.5, zorder=3, label="marginal gain")
    a1.plot(xs, cum, "o-", color="#d7301f", markersize=4.0, zorder=4,
            label="cumulative")
    for x, cc in zip(xs, cum):
        a1.text(x, cc + 3, f"{cc:.0f}%", ha="center", fontsize=6.8,
                color="#d7301f")
    a1.set_xticks(xs)
    a1.set_xlabel("Number of vulnerability scanners")
    a1.set_ylabel("Distinct vulns recovered (%)")
    a1.set_ylim(0, 116)
    a1.legend(loc="center right", fontsize=6.6, bbox_to_anchor=(1.0, 0.40))
    a1.set_title("(b) marginal Nth-scanner gain")

    # ---- (c) all findings vs distinct groups by severity ----
    a = PL["afig2_ctab4"]
    sev_all = a["sev_all_findings"]
    sev_dist = a["sev_distinct_groups"]
    order = ["critical", "high", "medium", "low", "info", "unknown"]
    order = [s for s in order if sev_all.get(s, 0) or sev_dist.get(s, 0)]
    labels = {"critical": "Crit.", "high": "High", "medium": "Med.",
              "low": "Low", "info": "Info", "unknown": "Unr."}
    allv = [sev_all.get(s, 0) for s in order]
    dstv = [sev_dist.get(s, 0) for s in order]
    a2 = ax[2]
    figstyle.grid(a2, "y")
    x = np.arange(len(order))
    bw = 0.38
    a2.bar(x - bw / 2, allv, bw, color="#4575b4", label="all findings",
           edgecolor="white", linewidth=0.4, zorder=3)
    a2.bar(x + bw / 2, dstv, bw, color="#d73027",
           label="distinct (CVE, pkg)", edgecolor="white", linewidth=0.4,
           zorder=3)
    a2.set_xticks(x)
    a2.set_xticklabels([labels[s] for s in order], rotation=25, ha="right")
    a2.set_ylabel("Vulnerability count")
    a2.yaxis.set_major_formatter(mfmt)
    a2.set_yscale("log")
    a2.legend(loc="upper right", fontsize=6.6)
    a2.margins(y=0.20)
    a2.set_title("(c) all vs distinct, by severity")

    fig.tight_layout(w_pad=1.6)
    save(fig, "fig_panel_divergence")


if __name__ == "__main__":
    fig_pull_vs_vuln()
    fig_allvsdistinct()
    fig_secret_cdf()
    fig_crawl_cdf()
    fig_marginal_scanner()
    fig_panel_divergence()
    print("DONE")
