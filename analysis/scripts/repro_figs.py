#!/usr/bin/env python3
"""
Graphical reproductions of prior Docker Hub measurement studies,
for the Section "Reproducing Prior Docker Hub Analyses".

2x1 panel:
 (a) Liu et al. 2020 -- prevalence of high/critical vulnerabilities,
     official vs. community images: the values reported by Liu (2020)
     alongside those measured in this corpus.
 (b) Wist et al. 2021 -- share of severe vulnerabilities
     (high+critical) by ecosystem class (OS vs. language).

All numbers come from repro_analysis.json (already computed). Liu's values
are those reported in their own paper (~30% official, >64% community).
Output: figures/fig_repro_panel.pdf
"""
import json
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import figstyle

OUT = "."
R = json.load(open(os.path.join(OUT, "repro_analysis.json")))
figstyle.apply()

fig, ax = plt.subplots(1, 2, figsize=(7.0, 2.4))

# (a) Liu et al. 2020: high/critical prevalence, official vs community
liu = R["liu"]
# values reported by Liu et al. 2020 (ESORICS): ~30% official, >64% community.
liu_reported = {"official": 30.0, "community": 64.0}
groups = ["Official", "Community"]
reported = [liu_reported["official"], liu_reported["community"]]
ours = [liu["official_hc_pct"], liu["community_hc_pct"]]
x = np.arange(len(groups))
w = 0.36
figstyle.grid(ax[0], "y")
b1 = ax[0].bar(x - w / 2, reported, w, color="#92c5de",
               edgecolor="#444444", linewidth=0.4, zorder=3,
               label="Liu et al.\\ 2020")
b2 = ax[0].bar(x + w / 2, ours, w, color="#b2182b",
               edgecolor="#444444", linewidth=0.4, zorder=3,
               label="This corpus (2026)")
ax[0].set_xticks(x)
ax[0].set_xticklabels(groups)
ax[0].set_ylabel("Images with high/critical vuln. (%)")
ax[0].set_xlabel("Image type")
ax[0].set_title("(a) Liu et al.\\ 2020")
ax[0].set_ylim(0, 109)
# horizontal legend strip above the panel title: the bars and their value
# labels fill the plot area, so an in-axes legend would overlap them.
ax[0].legend(loc="lower center", bbox_to_anchor=(0.5, 1.10), ncol=2,
             fontsize=6.5, columnspacing=1.0, handlelength=1.1,
             handletextpad=0.4)
for bars in (b1, b2):
    for b in bars:
        v = b.get_height()
        ax[0].text(b.get_x() + b.get_width() / 2, v + 1.5,
                   f"{v:.0f}" if v == int(v) else f"{v:.1f}",
                   ha="center", va="bottom", fontsize=6.5, zorder=4)

# (b) Wist et al. 2021: severe findings by ecosystem class
wist = R["wist"]["sev_findings_by_eco_class"]
total = sum(wist.values())
order = ["os", "lang", "other"]
labels = ["OS package\necosystems", "Language\necosystems", "Other"]
shares = [100.0 * wist.get(k, 0) / total for k in order]
colors = ["#4575b4", "#d6604d", "#bbbbbb"]
figstyle.grid(ax[1], "y")
bars = ax[1].bar(labels, shares, color=colors, width=0.62,
                 edgecolor="#444444", linewidth=0.4, zorder=3)
ax[1].set_ylabel("Share of high/critical findings (%)")
ax[1].set_xlabel("Package ecosystem class")
ax[1].set_title("(b) Wist et al.\\ 2021")
ax[1].set_ylim(0, 92)
for b, v in zip(bars, shares):
    ax[1].text(b.get_x() + b.get_width() / 2, v + 1.4, f"{v:.1f}",
               ha="center", va="bottom", fontsize=6.8, zorder=4)

fig.tight_layout(w_pad=2.0)
os.makedirs(os.path.join(OUT, "figures"), exist_ok=True)
fig.savefig(os.path.join(OUT, "figures", "fig_repro_panel.pdf"),
            bbox_inches="tight", pad_inches=0.03)
plt.close(fig)
print("wrote figures/fig_repro_panel.pdf")
print("  liu reported  :", liu_reported)
print("  liu ours      :", {"official": ours[0], "community": ours[1]})
print("  wist shares   :", dict(zip(order, [round(s, 1) for s in shares])))
