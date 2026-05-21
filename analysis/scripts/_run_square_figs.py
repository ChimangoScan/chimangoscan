#!/usr/bin/env python3
"""
Figuras do paper agrupadas em PAINEIS unicos (grids), uma legenda por painel
no LaTeX -- evita captions estreitas e compridas.

  figures/fig_panel_results.pdf    (1x3) vulns/imagem, severidade, tempo
  figures/fig_panel_inventory.pdf  (1x3) ecossistemas, concordancia, secrets
  figures/fig_panel_offcomm.pdf    (1x2) oficial x comunidade: vulns e secrets

Le analyze_db.stats.json, step3_recompute.json, fig_official_vs_community_stats.json.
"""
import json, os, math
from collections import Counter

OUT = '/mnt/win_ssd/chimangoscan-paper'  # overridden by regenerate_all.py
SCANNERS = ["syft", "trivy", "grype", "osv", "dockle", "trufflehog"]
SEVS = ["critical", "high", "medium", "low", "info", "unknown"]


def figstyle_grid_x(ax):
    """Grid sutil no eixo x, atras dos dados."""
    ax.set_axisbelow(True)
    ax.grid(axis="x", color="#d8d8d8", linewidth=0.5, zorder=0)


def pct(sv, q):
    n = len(sv)
    if n == 0:
        return 0.0
    if n == 1:
        return float(sv[0])
    k = (n - 1) * (q / 100.0)
    lo, hi = math.floor(k), math.ceil(k)
    if lo == hi:
        return float(sv[int(k)])
    return sv[lo] * (hi - k) + sv[hi] * (k - lo)


def main():
    A = json.load(open(os.path.join(OUT, "analyze_db.stats.json")))
    S3 = json.load(open(os.path.join(OUT, "step3_recompute.json")))
    OC = json.load(open(os.path.join(OUT, "fig_official_vs_community_stats.json")))
    EX = json.load(open(os.path.join(OUT, "extra_analysis.json")))

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FuncFormatter
    import numpy as np

    plt.rcParams.update({
        "font.size": 9, "axes.labelsize": 9, "axes.titlesize": 9.5,
        "xtick.labelsize": 8, "ytick.labelsize": 8, "legend.fontsize": 6.8,
        "figure.dpi": 300, "savefig.dpi": 300,
        "axes.spines.top": False, "axes.spines.right": False,
        "axes.linewidth": 0.7, "xtick.major.width": 0.7, "ytick.major.width": 0.7,
        "lines.linewidth": 1.4,
    })
    SEV_COLORS = {"critical": "#7a0177", "high": "#d7301f", "medium": "#fc8d59",
                  "low": "#fee08b", "info": "#91bfdb", "unknown": "#bdbdbd"}

    def mil(x, _p=None):
        ax = abs(x)
        if ax >= 1e6:
            return f"{x/1e6:.0f}M" if (ax % 1e6 < 1 or ax >= 1e7) else f"{x/1e6:.1f}M"
        if ax >= 1e3:
            return f"{x/1e3:.0f}k"
        return f"{x:.0f}"
    mfmt = FuncFormatter(mil)
    os.makedirs(os.path.join(OUT, "figures"), exist_ok=True)

    def savep(fig, base):
        fig.savefig(os.path.join(OUT, "figures", base + ".pdf"),
                    bbox_inches="tight", pad_inches=0.03)
        plt.close(fig)
        print("wrote figures/" + base + ".pdf")

    # ===== PAINEL 1: vulns/imagem, severidade, tempo =====
    fig, ax = plt.subplots(1, 3, figsize=(9.2, 2.45))

    # (a) CDF vulns por imagem
    vpi = sorted(A["vulns_per_image"])
    x = np.array(vpi, dtype=float)
    y = np.arange(1, len(x) + 1) / len(x)
    ax[0].plot(x, y, color="#2166ac")
    cap = pct(vpi, 99)
    med = pct(vpi, 50)
    ax[0].set_xlim(0, max(cap, 1)); ax[0].set_ylim(0, 1.02)
    ax[0].axvline(med, color="#d7301f", ls="--", lw=1.0)
    ax[0].text(med + cap * 0.04, 0.10, f"median {med:.0f}", color="#d7301f", fontsize=7.5)
    ax[0].set_xlabel("Vulnerabilities per image")
    ax[0].set_ylabel("Cumulative fraction")
    ax[0].xaxis.set_major_formatter(mfmt)
    ax[0].set_title("(a)")

    # (b) severidade por scanner (osv/dockle pos-correcao)
    sbs = {k: dict(v) for k, v in A["sev_by_scanner"].items()}
    sbs["osv"] = S3["osv"]["after"]
    sbs["dockle"] = S3["dockle"]["after"]
    scs = [s for s in SCANNERS if s in sbs and sum(sbs[s].values()) > 0]
    sclab = {"syft": "Syft", "trivy": "Trivy", "grype": "Grype", "osv": "OSV",
             "dockle": "Dockle", "trufflehog": "TrufHog"}
    ax[1].grid(axis="y", color="#d8d8d8", linewidth=0.5, zorder=0)
    ax[1].set_axisbelow(True)
    bottom = np.zeros(len(scs))
    xlab = [sclab.get(s, s) for s in scs]
    for sev in SEVS:
        vals = np.array([sbs[s].get(sev, 0) for s in scs], dtype=float)
        ax[1].bar(xlab, vals, bottom=bottom, label=sev, color=SEV_COLORS[sev],
                  edgecolor="white", linewidth=0.3, width=0.66, zorder=3)
        bottom += vals
    ax[1].set_ylabel("Findings"); ax[1].set_xlabel("Scanner")
    ax[1].yaxis.set_major_formatter(mfmt)
    ax[1].tick_params(axis="x", labelrotation=38)
    for l in ax[1].get_xticklabels():
        l.set_ha("right")
    # legenda horizontal acima do titulo do painel, fora da area de barras
    ax[1].legend(ncol=6, frameon=False, fontsize=5.8, loc="lower center",
                 bbox_to_anchor=(0.5, 1.13), columnspacing=0.7,
                 handlelength=1.0, handletextpad=0.4)
    ax[1].margins(y=0.12)
    ax[1].set_title("(b)")

    # (c) tempo de scan por scanner (sem clair, linear)
    data, labels = [], []
    for s in SCANNERS:
        v = A["wall_by_scanner"].get(s, [])
        if v:
            data.append(v); labels.append(sclab.get(s, s))
    bp = ax[2].boxplot(data, tick_labels=labels, showfliers=False, patch_artist=True,
                       widths=0.6, medianprops=dict(color="#222", linewidth=1.0),
                       whiskerprops=dict(linewidth=0.7), capprops=dict(linewidth=0.7),
                       boxprops=dict(linewidth=0.7))
    for p in bp["boxes"]:
        p.set_facecolor("#9ecae1"); p.set_edgecolor("#2166ac")
    ax[2].set_ylabel("Wall time per scan (s)"); ax[2].set_xlabel("Scanner")
    ax[2].tick_params(axis="x", labelrotation=40)
    for l in ax[2].get_xticklabels():
        l.set_ha("right")
    ax[2].set_title("(c)")
    fig.tight_layout(w_pad=1.6)
    savep(fig, "fig_panel_results")

    # ===== PAINEL 2: ecossistemas SBOM, tipos de secret, pacotes/imagem =====
    # painel compacto (1x3): barras horizontais com grid e rotulos de valor,
    # mais a distribuicao do numero de componentes por imagem (CDF).
    fig, ax = plt.subplots(1, 3, figsize=(9.2, 2.05))

    def hbar(a, names, vals, color):
        a.grid(axis="x", color="#d8d8d8", linewidth=0.5, zorder=0)
        a.set_axisbelow(True)
        bars = a.barh(names, vals, color=color, height=0.70, zorder=3)
        vmax = max(vals)
        for b, v in zip(bars, vals):
            a.text(v + vmax * 0.02, b.get_y() + b.get_height() / 2, mil(v),
                   ha="left", va="center", fontsize=6.4)
        a.set_xlim(0, vmax * 1.18)

    # (a) ecossistemas SBOM
    eco = Counter(A["ecosystem_count"]).most_common(8)
    names = [e[0] for e in eco][::-1]; vals = [e[1] for e in eco][::-1]
    hbar(ax[0], names, vals, "#3182bd")
    ax[0].set_xlabel("SBOM components"); ax[0].xaxis.set_major_formatter(mfmt)
    ax[0].set_title("(a)")

    # (b) tipos de secret
    styp = Counter(A["secret_type"]).most_common(8)
    sn = [(s[0][:12] + ".." if len(s[0]) > 14 else s[0]) for s in styp][::-1]
    sv = [s[1] for s in styp][::-1]
    hbar(ax[1], sn, sv, "#cb6a3e")
    ax[1].set_xlabel("Secret detections"); ax[1].xaxis.set_major_formatter(mfmt)
    ax[1].set_title("(b)")

    # (c) CDF do numero de componentes (pacotes) por imagem inventariados
    #     pelo Syft -- corte em p99 para nao ser dominado pela cauda longa.
    cpi = sorted(A["components_per_image"])
    cx = np.array(cpi, dtype=float)
    cy = np.arange(1, len(cx) + 1) / len(cx)
    ccap = pct(cpi, 99)
    cmed = pct(cpi, 50)
    ax[2].grid(axis="both", color="#d8d8d8", linewidth=0.5, zorder=0)
    ax[2].set_axisbelow(True)
    ax[2].plot(cx, cy, color="#3182bd", zorder=3)
    ax[2].set_xlim(0, max(ccap, 1)); ax[2].set_ylim(0, 1.02)
    ax[2].axvline(cmed, color="#d7301f", ls="--", lw=1.0, zorder=2)
    ax[2].text(cmed + ccap * 0.05, 0.10, f"median {cmed:.0f}",
               color="#d7301f", fontsize=7.0)
    ax[2].set_xlabel("Components per image")
    ax[2].set_ylabel("Cumulative fraction")
    ax[2].xaxis.set_major_formatter(mfmt)
    ax[2].set_title("(c)")
    fig.tight_layout(w_pad=1.6)
    savep(fig, "fig_panel_inventory")

    # ===== PAINEL 3: oficial x comunidade (1x2) =====
    fig, ax = plt.subplots(1, 2, figsize=(6.4, 2.35))
    grp = ["Official", "Community"]
    # cores sobrias: azul-petroleo para oficial, ocre/vermelho-tijolo para comunidade
    gcol = ["#2c7fb8", "#cb6a3e"]

    # (a) violin: distribuicao completa de vulns/imagem, oficial x comunidade.
    # escala log (max ~113k); apenas imagens com >=1 vuln entram no violino.
    oc_d = EX["offcomm"]
    off = np.array([v for v in oc_d["official_vulns"] if v > 0], dtype=float)
    com = np.array([v for v in oc_d["community_vulns"] if v > 0], dtype=float)
    dat = [np.log10(off), np.log10(com)]
    vp = ax[0].violinplot(dat, positions=[1, 2], showmedians=False,
                          showextrema=False, widths=0.72)
    for body, cc in zip(vp["bodies"], gcol):
        body.set_facecolor(cc); body.set_alpha(0.62); body.set_edgecolor(cc)
        body.set_linewidth(1.0)
    # quartis + mediana: marca a mediana com traco grosso, Q1/Q3 com tracos finos
    for i, key in enumerate(("official_vulns", "community_vulns"), start=1):
        arr = np.array([v for v in oc_d[key] if v > 0], dtype=float)
        q1, q3 = np.percentile(arr, [25, 75])
        ax[0].vlines(i, np.log10(q1), np.log10(q3), color="#333", linewidth=4.2,
                     zorder=3, alpha=0.55)
    # mediana desenhada no valor oficial do JSON (inclui imagens com 0 vulns)
    medv = [OC["OFFICIAL"]["median"], OC["COMMUNITY"]["median"]]
    for i, mv in enumerate(medv, start=1):
        ax[0].scatter([i], [np.log10(mv)], s=26, color="white",
                      edgecolor="#222", linewidth=1.1, zorder=5)
        ax[0].text(i + 0.30, np.log10(mv), f"med. {mv:.0f}", ha="left",
                   va="center", fontsize=7.2, fontweight="bold")
    ax[0].set_xticks([1, 2]); ax[0].set_xticklabels(grp)
    ax[0].set_xlim(0.45, 2.75)
    ax[0].set_ylabel("Vulnerabilities per image")
    ticks = [0, 1, 2, 3, 4, 5]
    ax[0].set_yticks(ticks)
    ax[0].set_yticklabels([mil(10 ** t) for t in ticks])
    ax[0].set_ylim(-0.3, 5.3)
    ax[0].set_title("(a)")

    # (b) duas proporcoes comparaveis (0-100%): prevalencia de >=1 secret e
    #     fracao de imagens acima da mediana de vulns do corpus. Barras
    #     horizontais agrupadas -- leitura limpa, rotulos no fim de cada barra.
    corpus_med = float(np.median(oc_d["official_vulns"] + oc_d["community_vulns"]))
    above = []
    for key in ("official_vulns", "community_vulns"):
        arr = oc_d[key]
        above.append(100.0 * sum(1 for v in arr if v > corpus_med) / len(arr))
    secret = [100 * OC["OFFICIAL"]["secret_frac"],
              100 * OC["COMMUNITY"]["secret_frac"]]
    metrics = [("Vuln. above\ncorpus median", above), ("$\\geq$1 secret", secret)]
    ypos = np.arange(len(metrics))
    bw = 0.34
    figstyle_grid_x(ax[1])
    for gi, (gname, gc) in enumerate(zip(grp, gcol)):
        vals = [m[1][gi] for m in metrics]
        bars = ax[1].barh(ypos + (0.5 - gi) * bw, vals, bw, color=gc,
                          label=gname, edgecolor="white", linewidth=0.4,
                          zorder=3)
        for b, v in zip(bars, vals):
            ax[1].text(v + 1.5, b.get_y() + b.get_height() / 2, f"{v:.0f}%",
                       ha="left", va="center", fontsize=7.2)
    ax[1].set_yticks(ypos)
    ax[1].set_yticklabels([m[0] for m in metrics])
    ax[1].set_xlabel("Images (%)"); ax[1].set_xlim(0, 112)
    ax[1].set_xticks([0, 25, 50, 75, 100])
    ax[1].set_ylim(-0.7, 1.7)
    ax[1].invert_yaxis()
    ax[1].legend(frameon=False, fontsize=6.6, ncol=2, loc="lower center",
                 bbox_to_anchor=(0.5, 1.10), columnspacing=1.2,
                 handlelength=1.1, handletextpad=0.4)
    ax[1].set_title("(b)")
    fig.tight_layout(w_pad=2.0)
    savep(fig, "fig_panel_offcomm")
    print("DONE")


if __name__ == "__main__":
    main()
