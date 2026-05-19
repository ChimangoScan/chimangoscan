#!/usr/bin/env python3
"""
Figuras: Venn-3 de concordancia entre scanners, boxplot oficial x comunidade,
e linha do tempo dos estudos de Docker Hub. Saida em figures/.
"""
import json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Circle
import numpy as np
import figstyle

OUT = "/mnt/win_ssd/chimangoscan-paper"
figstyle.apply()
EX = json.load(open(os.path.join(OUT, "extra_analysis.json")))


def save(fig, base):
    os.makedirs(os.path.join(OUT, "figures"), exist_ok=True)
    fig.savefig(os.path.join(OUT, "figures", base + ".pdf"),
                bbox_inches="tight", pad_inches=0.03)
    plt.close(fig)
    print("wrote figures/" + base + ".pdf")


def m(x):
    return f"{x/1e6:.1f}M"


# ===== Venn-3: concordancia Trivy / Grype / OSV =====
v = EX["venn"]
fig, ax = plt.subplots(figsize=(3.1, 2.7))
r = 1.0
c = {"T": (-0.42, 0.30), "G": (0.42, 0.30), "O": (0.0, -0.42)}
cols = {"T": "#4575b4", "G": "#d73027", "O": "#1a9850"}
for k, (x, y) in c.items():
    ax.add_patch(Circle((x, y), r, alpha=0.32, facecolor=cols[k],
                         edgecolor=cols[k], linewidth=1.0))
# rotulos das regioes (7)
ax.text(-0.95, 0.95, m(v["trivy_only"]), ha="center", fontsize=8)
ax.text(0.95, 0.95, m(v["grype_only"]), ha="center", fontsize=8)
ax.text(0.0, -1.18, m(v["osv_only"]), ha="center", fontsize=8)
ax.text(0.0, 0.66, m(v["trivy_grype"]), ha="center", fontsize=8)
ax.text(-0.62, -0.32, m(v["trivy_osv"]), ha="center", fontsize=7.5)
ax.text(0.62, -0.32, m(v["grype_osv"]), ha="center", fontsize=7.5)
ax.text(0.0, 0.05, m(v["all3"]), ha="center", fontsize=8, fontweight="bold")
# nomes dos conjuntos
ax.text(-1.05, 1.32, "Trivy", color=cols["T"], fontsize=9, fontweight="bold")
ax.text(0.70, 1.32, "Grype", color=cols["G"], fontsize=9, fontweight="bold")
ax.text(0.0, -1.62, "OSV-Scanner", color=cols["O"], ha="center", fontsize=9,
        fontweight="bold")
ax.set_xlim(-2.0, 2.0); ax.set_ylim(-1.9, 1.6)
ax.set_aspect("equal"); ax.axis("off")
save(fig, "fig_venn")

# NOTA: o painel oficial x comunidade (fig_panel_offcomm) e gerado por
# square_figs.py (violino + barra); nao duplicar aqui.

# ===== linha do tempo dos estudos =====
# (prevalencia de imagens com >=1 vulnerabilidade conhecida; metricas e
#  scanners diferem entre estudos -- a metrica/scanner de cada ponto vai
#  anotada no rotulo, ver caption. Numeros extraidos dos papers em refs/.)
#   Shu 2017      : >80% with a high-severity vuln, Clair                [shu]
#   Zerouali 2019 : Debian-based images ~all affected (technical lag)    [zer]
#   Liu 2020      : 64% of community images high/critical, Anchore       [liu]
#   Wist 2021     : 82.2% with >=1 vuln (17.8% vuln-free), 2.5k images   [wist]
#   Mills 2023    : 374/380 = 98.4% with >=1 vuln, OGMA (6 scanners)     [mills]
#   Dr. Docker 25 : 93.7% with a known vulnerability, Anchore            [drd]
#   This work 26  : 97.6% with a known vulnerability, 6 scanners
studies = [
    ("Shu\n2017", 2017, 80, "high-sev, Clair"),
    ("Zerouali\n2019", 2019, 100, "Debian, tech-lag"),
    ("Liu\n2020", 2020, 64, "high/crit, Anchore"),
    ("Wist\n2021", 2021, 82.2, ">=1 vuln, OSS scanner"),
    ("Mills\n2023", 2023, 98.4, ">=1 vuln, 6 scanners"),
    ("Dr. Docker\n2025", 2025, 93.7, "known vuln, Anchore"),
    ("This work\n2026", 2026, 97.6, "known vuln, 6 scanners"),
]
fig, ax = plt.subplots(figsize=(3.35, 2.0))
figstyle.grid(ax, "y")
xs = [s[1] for s in studies]
ys = [s[2] for s in studies]
ax.plot(xs, ys, "-", color="#999999", linewidth=1.0, zorder=2)
# deslocamento manual para evitar sobreposicao perto do topo
DX = {"Liu\n2020": -2, "Wist\n2021": 4, "Mills\n2023": -3,
      "Dr. Docker\n2025": -13, "This work\n2026": 7}
for label, x, y, sc in studies:
    last = label.startswith("This")
    ax.scatter([x], [y], s=30, color="#b2182b" if last else "#4575b4",
               zorder=4, edgecolor="#333", linewidth=0.5)
    # rotulos perto do topo vao abaixo do ponto para nao sair do eixo (y<=100)
    if y >= 92:
        dy, va = -8, "top"
    else:
        dy, va = 7, "bottom"
    dx = DX.get(label, 0)
    ax.annotate(label, (x, y), textcoords="offset points", xytext=(dx, dy),
                ha="center", va=va, fontsize=5.8,
                fontweight="bold" if last else "normal")
ax.set_xlabel("Year of study")
ax.set_ylabel("Images with a known\nvulnerability (%)")
# eixo de valores limitado a 100; folga minima so para o marcador em 100 nao
# ser cortado pela borda. ticks param em 100.
ax.set_ylim(45, 105)
ax.set_yticks([50, 60, 70, 80, 90, 100])
ax.set_xlim(2015.5, 2027.5)
save(fig, "fig_timeline")
print("DONE")
