"""Estilo de figura nivel publicacao, compartilhado pelos scripts de figura.
Fonte serif (casa com o texto do paper), grid sutil, tracos finos."""
import matplotlib


def apply():
    import matplotlib.pyplot as plt
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Liberation Serif", "Nimbus Roman", "Times New Roman",
                       "DejaVu Serif"],
        "mathtext.fontset": "cm",
        "font.size": 9, "axes.labelsize": 9, "axes.titlesize": 9.5,
        "xtick.labelsize": 8, "ytick.labelsize": 8, "legend.fontsize": 7.6,
        "figure.dpi": 300, "savefig.dpi": 300,
        "axes.spines.top": False, "axes.spines.right": False,
        "axes.linewidth": 0.6, "axes.axisbelow": True,
        "axes.titlepad": 4.0, "axes.labelpad": 2.5,
        "xtick.major.width": 0.6, "ytick.major.width": 0.6,
        "xtick.major.size": 2.8, "ytick.major.size": 2.8,
        "lines.linewidth": 1.6,
        "legend.frameon": False, "legend.handlelength": 1.6,
    })


def grid(ax, axis="y"):
    """Grid sutil atras dos dados, no eixo de valores."""
    ax.set_axisbelow(True)
    ax.grid(axis=axis, color="#d8d8d8", linewidth=0.5, zorder=0)
