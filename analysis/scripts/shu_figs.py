#!/usr/bin/env python3
"""
Single panel (1x3 grid) of the Shu 2017 analyses reproduced in this work:
(a) severity of the worst finding, (b) CVEs per year, (c) vulnerabilities vs. age.
Output: figures/fig_shu_panel.pdf
"""
import json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
import numpy as np
import figstyle

OUT = "."
PA = json.load(open(os.path.join(OUT, "paper_analysis.json")))
figstyle.apply()

SEV_COLORS = {"critical": "#762a83", "high": "#d6604d", "medium": "#f4a582",
              "low": "#fddbc7", "none": "#92c5de"}


def mil(x, _p=None):
    ax = abs(x)
    if ax >= 1e6:
        return f"{x/1e6:.0f}M"
    if ax >= 1e3:
        return f"{x/1e3:.0f}k"
    return f"{x:.0f}"
mfmt = FuncFormatter(mil)

fig, ax = plt.subplots(1, 3, figsize=(9.2, 2.45))

# (a) images by the severity of the worst finding
ms = PA["most_severe"]
n = PA["n_reports"]
order = ["none", "low", "medium", "high", "critical"]
vals = [100.0 * ms.get(k, 0) / n for k in order]
figstyle.grid(ax[0], "y")
bars = ax[0].bar(order, vals, color=[SEV_COLORS[k] for k in order], width=0.70,
                 edgecolor="#444444", linewidth=0.4, zorder=3)
ax[0].set_ylabel("Images (%)")
ax[0].set_xlabel("Most severe vulnerability")
ax[0].set_title("(a)")
ax[0].tick_params(axis="x", labelrotation=30)
for l in ax[0].get_xticklabels():
    l.set_ha("right")
ax[0].margins(y=0.16)
for b, v in zip(bars, vals):
    if v >= 0.5:
        ax[0].text(b.get_x() + b.get_width() / 2, v, f"{v:.1f}", ha="center",
                   va="bottom", fontsize=7, zorder=4)

# (b) distinct CVEs by publication year
cy = {int(k): v for k, v in PA["cve_distinct_by_year"].items()}
years = sorted(y for y in cy if y <= 2026)
figstyle.grid(ax[1], "y")
ax[1].bar([str(y) for y in years], [cy[y] for y in years], color="#3a6ea5",
          width=0.80, zorder=3)
ax[1].set_ylabel("Distinct CVEs detected")
ax[1].set_xlabel("CVE publication year")
ax[1].set_title("(b)")
_ticks = list(range(0, len(years), 4))
if len(years) - 1 not in _ticks:        # always show the first and last year
    _ticks.append(len(years) - 1)
ax[1].set_xticks(_ticks)
ax[1].set_xticklabels([str(years[i]) for i in _ticks], rotation=45, ha="right")
ax[1].yaxis.set_major_formatter(mfmt)

# (c) vulnerabilities vs. image age
TA = json.load(open(os.path.join(OUT, "temporal_analysis.json")))
pairs = TA.get("pairs", [])
by_year = {}
for age_d, nv in pairs:
    yr = max(int(age_d // 365), 0)
    by_year.setdefault(yr, []).append(nv)
xs = sorted(y for y in by_year if len(by_year[y]) >= 30)
med = [float(np.median(by_year[y])) for y in xs]
p75 = [float(np.percentile(by_year[y], 75)) for y in xs]
figstyle.grid(ax[2], "y")
ax[2].plot(xs, med, "o-", color="#b2182b", markersize=3.6, label="median", zorder=3)
ax[2].plot(xs, p75, "s--", color="#ef8a62", markersize=3.2, label="75th pct.",
           zorder=3)
ax[2].set_xlabel("Image age (years since update)")
ax[2].set_ylabel("Vulnerabilities per image")
ax[2].set_title("(c)")
ax[2].legend(loc="upper left")
ax[2].margins(y=0.13)

fig.tight_layout(w_pad=1.6)
os.makedirs(os.path.join(OUT, "figures"), exist_ok=True)
fig.savefig(os.path.join(OUT, "figures", "fig_shu_panel.pdf"),
            bbox_inches="tight", pad_inches=0.03)
plt.close(fig)
print("wrote figures/fig_shu_panel.pdf  (temporal coverage %.1f%%)"
      % TA.get("coverage_pct", 0))
