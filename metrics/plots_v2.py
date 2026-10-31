"""
plots_v2.py -- figures du chapitre 4 a partir de results/*.json.

Usage : python metrics/plots_v2.py results/ media/

  handshake-envs.png : duree du handshake (authentification serveur et mTLS),
                       classique vs post-quantique, par environnement ;
  reuse-envs.png     : latence d'acces service -> service avec et sans
                       reutilisation des connexions, par environnement.
"""

import json
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

CLASSIC, PQC = "#2a78d6", "#eb6834"   # palette categorielle, emplacements 1 et 2
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"
ENVS = [("aws", "AWS, même\ninstance"), ("vm", "VM locale"),
        ("useast", "AWS\ninter-régions"), ("vmaws", "VM → AWS\n(Internet)")]


def load(d, env, mode, var):
    p = os.path.join(d, "%s-%s-%s.json" % (env, mode, var))
    if not os.path.exists(p):
        return None
    with open(p) as f:
        return json.load(f)


def med(r, *path):
    for k in path:
        if r is None or k not in r:
            return None
        r = r[k]
    return r


def style(ax, ylabel):
    ax.set_ylabel(ylabel, color=MUTED, fontsize=10)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(MUTED)
    ax.tick_params(colors=MUTED, labelsize=9)


def bars(ax, groups, series, ylabel, title):
    """groups : etiquettes ; series : [(nom, couleur, valeurs)]."""
    n = len(series)
    w = 0.8 / n
    for i, (name, color, vals) in enumerate(series):
        xs = [g + (i - (n - 1) / 2) * w for g in range(len(groups))]
        ys = [v if v is not None else 0 for v in vals]
        b = ax.bar(xs, ys, w * 0.92, color=color, label=name, zorder=2)
        for rect, v in zip(b, vals):
            if v is not None:
                ax.annotate("%.0f" % v if v >= 10 else "%.1f" % v,
                            (rect.get_x() + rect.get_width() / 2, rect.get_height()),
                            xytext=(0, 2), textcoords="offset points", ha="center",
                            fontsize=8, color=INK)
    ax.set_xticks(range(len(groups)))
    ax.set_xticklabels(groups)
    ax.set_title(title, fontsize=11, color=INK, loc="left")
    style(ax, ylabel)


def main(d, out):
    envs = [(e, lab) for e, lab in ENVS if load(d, e, "pqc", "reuse1")]
    labels = [lab for _, lab in envs]

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
    for ax, key, title in ((axes[0], "handshake_server_auth", "Authentification du serveur"),
                           (axes[1], "handshake_mtls", "Authentification mutuelle (mTLS)")):
        series = [(name, c, [med(load(d, e, m, "reuse1"), key, "tls_ms", "median") for e, _ in envs])
                  for name, c, m in (("Classique (X25519, RSA-3072)", CLASSIC, "classical"),
                                     ("Post-quantique (HQC-1, CROSS)", PQC, "pqc"))]
        bars(ax, labels, series, "Durée médiane du handshake (ms)", title)
    axes[0].legend(frameon=False, fontsize=9, loc="upper left")
    fig.tight_layout()
    fig.savefig(os.path.join(out, "handshake-envs.png"), dpi=200)

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
    for ax, mode, title in ((axes[0], "classical", "Classique"), (axes[1], "pqc", "Post-quantique")):
        c = CLASSIC if mode == "classical" else PQC
        series = [("Connexions réutilisées", c, [med(load(d, e, mode, "reuse1"), "s2s_access", "median") for e, _ in envs]),
                  ("Nouvelle connexion par requête", "#9a9893", [med(load(d, e, mode, "reuse0"), "s2s_access", "median") for e, _ in envs])]
        bars(ax, labels, series, "Latence médiane d'accès (ms)", title)
        ax.legend(frameon=False, fontsize=9, loc="upper left")
    ymax = max(a.get_ylim()[1] for a in axes)
    for a in axes:
        a.set_ylim(0, ymax)
    fig.tight_layout()
    fig.savefig(os.path.join(out, "reuse-envs.png"), dpi=200)
    print("figures ecrites dans", out)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
