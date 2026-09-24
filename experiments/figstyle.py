#!/usr/bin/env python3
"""Unified publication style for Post-Quantum Biscuit figures.

Design intent
-------------
* Semantic, colour-vision-safe palette (Okabe & Ito): a reader learns the
  colour *meaning* once and meets it consistently in every figure.
    classical baseline -> near black;   ML-DSA -> blue;   FN-DSA -> bluish green
    SLH-DSA -> vermillion (heavy, root only);   hybrid -> sky blue
    mixed (recommended) -> reddish purple, drawn heavier
* No background grid (journal style); top/right spines removed.
* Two reusable idioms solve the over-crowded line problem:
    small multiples (one algorithm per panel, Ed shown as a faint reference);
    direct end-of-line labels on the few argument figures (no legend hunt).
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# ---- Okabe & Ito (colour-vision safe) ----
OI = {"black": "#000000", "orange": "#E69F00", "sky": "#56B4E9",
      "green": "#009E73", "yellow": "#F0E442", "blue": "#0072B2",
      "vermillion": "#D55E00", "purple": "#CC79A7"}

FAMILY_COLOR = {"ed": "#111111", "ml": OI["blue"], "fn": OI["green"],
                "slh": OI["vermillion"], "hyb": OI["sky"], "mix": OI["purple"]}

# neutral comparison colours for grouped bars (build / phase)
BUILD_COLOR = {"avx2": "#3B6FA8", "portable": "#E8A13A"}
PHASE_COLOR = {"keygen": "#9AA3A8", "sign": OI["green"], "realtime": OI["vermillion"]}

# ---- canonical algorithm keys -> family / labels ----
CANON = [
    "ed", "ml44", "ml65", "ml87", "fn512", "fn1024",
    "hyb-ml44", "hyb-fn512",
    "slh128s", "slh128f", "slh256s", "slh256f",
    "mix-ml87-fn512", "mix-slh256s-fn512", "mix-ml87-ml44",
    "mix-slh128s-fn512",
]
FAMILY = {**{k: "ml" for k in ("ml44", "ml65", "ml87")},
          **{k: "fn" for k in ("fn512", "fn1024")},
          **{k: "slh" for k in ("slh128s", "slh128f", "slh256s", "slh256f")},
          "ed": "ed", "hyb-ml44": "hyb", "hyb-fn512": "hyb",
          **{k: "mix" for k in ("mix-ml87-fn512", "mix-slh256s-fn512",
                                "mix-ml87-ml44", "mix-slh128s-fn512")}}
LONG = {
    "ed": "Ed25519", "ml44": "ML-DSA-44", "ml65": "ML-DSA-65",
    "ml87": "ML-DSA-87", "fn512": "FN-DSA-512", "fn1024": "FN-DSA-1024",
    "hyb-ml44": "Hyb Ed+ML44", "hyb-fn512": "Hyb Ed+FN512",
    "slh128s": "SLH-DSA-128s", "slh128f": "SLH-DSA-128f",
    "slh256s": "SLH-DSA-256s", "slh256f": "SLH-DSA-256f",
    "mix-ml87-fn512": "Mixed ML87/FN512",
    "mix-slh256s-fn512": "Mixed SLH256s/FN512",
    "mix-ml87-ml44": "Mixed ML87/ML44",
    "mix-slh128s-fn512": "Mixed SLH128s/FN512"}
SHORT = {
    "ed": "Ed", "ml44": "ML-44", "ml65": "ML-65", "ml87": "ML-87",
    "fn512": "FN-512", "fn1024": "FN-1024", "hyb-ml44": "Hyb+ML44",
    "hyb-fn512": "Hyb+FN512", "slh128s": "SLH-128s", "slh128f": "SLH-128f",
    "slh256s": "SLH-256s", "slh256f": "SLH-256f",
    "mix-ml87-fn512": "Mixed", "mix-slh256s-fn512": "Mixed",
    "mix-ml87-ml44": "Mixed", "mix-slh128s-fn512": "Mixed"}

# raw-name -> canonical key (covers every naming used across E5/E55/E56/E6/net)
_ALIAS = {
    "ed25519": "ed",
    "mldsa44": "ml44", "mldsa65": "ml65", "mldsa87": "ml87",
    "fndsa512": "fn512", "fndsa1024": "fn1024",
    "slhdsa128s": "slh128s", "slhdsa128f": "slh128f",
    "slhdsa256s": "slh256s", "slhdsa256f": "slh256f",
    "hyb-ed-mldsa44": "hyb-ml44", "hyb-ed-fndsa512": "hyb-fn512",
    "hybridedmldsa44": "hyb-ml44", "hybridedfndsa512": "hyb-fn512",
    "mix-mldsa87-fndsa512": "mix-ml87-fn512",
    "mix-slh256s-fndsa512": "mix-slh256s-fn512",
    "mix-mldsa87-mldsa44": "mix-ml87-ml44",
    # e6 profile names
    "all-ed": "ed", "all-mldsa44": "ml44", "all-fndsa512": "fn512",
    "hybrid-ed-mldsa44": "hyb-ml44", "hybrid-ed-fndsa512": "hyb-fn512",
    "mixed-mldsa87-root-fn": "mix-ml87-fn512",
    "mixed-slh128s-root-fn": "mix-slh128s-fn512",
}


def canon(raw):
    """Normalise any raw algorithm/profile name to a canonical key."""
    if raw in CANON:
        return raw
    k = str(raw).strip().lower()
    if k in _ALIAS:
        return _ALIAS[k]
    # capitalized E56 form, e.g. "Mldsa44" / "Fndsa512"
    if k in _ALIAS:
        return _ALIAS[k]
    raise KeyError(f"unknown algorithm name: {raw!r}")


def color_of(raw):
    return FAMILY_COLOR[FAMILY[canon(raw)]]


def family_of(raw):
    return FAMILY[canon(raw)]


def label_of(raw, short=False):
    c = canon(raw)
    return (SHORT if short else LONG)[c]


def setup():
    plt.rcParams.update({
        "font.size": 9, "axes.labelsize": 9.5, "axes.titlesize": 10.5,
        "legend.fontsize": 8, "xtick.labelsize": 8.2, "ytick.labelsize": 8.2,
        "figure.dpi": 200, "savefig.dpi": 200,
        "axes.grid": False, "axes.spines.top": False,
        "axes.spines.right": False, "axes.linewidth": 0.8,
        "axes.edgecolor": "#333333", "legend.frameon": False,
        "lines.linewidth": 1.7, "lines.markersize": 4,
        "font.family": "dejavu sans",
    })


def ed_reference(ax, x, y, **kw):
    """Draw the classical Ed curve as a faint shared reference in a panel."""
    opts = dict(color="#111111", lw=1.0, ls=(0, (4, 3)), alpha=0.55, zorder=1)
    opts.update(kw)
    return ax.plot(x, y, **opts)


def direct_label(ax, x_end, y_end, text, color, dy=0.0, dx=0.0,
                 ha="left", weight=None, size=7.6, fs=None):
    """Place a short name just past the last point of a curve."""
    return ax.annotate(text, xy=(x_end, y_end), xytext=(dx, dy),
                       textcoords="offset points", ha=ha, va="center",
                       fontsize=fs or size, color=color, fontweight=weight,
                       clip_on=False)


def small_multiples(fig, axes, xlabel, ylabel, title=None):
    """Tidy a small-multiple grid: labels only on the border panels."""
    for ax in axes.flat:
        ax.tick_params(labelsize=7.4, length=2.5)
    for ax in axes[-1]:
        ax.set_xlabel(xlabel, fontsize=8.6)
    for ax in axes[:, 0]:
        ax.set_ylabel(ylabel, fontsize=8.6)
    if title:
        fig.suptitle(title, fontsize=11, y=1.0)
