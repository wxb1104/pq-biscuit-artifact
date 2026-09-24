#!/usr/bin/env python3
"""Redraw all micro-benchmark figures for the CN manuscript.

Outputs publication figures to experiments/figures_v2/ with the unified
semantic style from figstyle.py.  Every statistic is read from the existing,
frozen analysis CSVs (no new measurements, no recomputed claims).
"""
import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

import figstyle as fs

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
OUT = os.path.join(HERE, "figures")
os.makedirs(OUT, exist_ok=True)
fs.setup()

UNIFORM = ["ed", "ml44", "ml65", "ml87", "fn512", "fn1024",
           "slh128s", "slh128f", "slh256s", "slh256f"]
ALL12 = ["ed", "ml44", "ml65", "ml87", "fn512", "fn1024",
         "hyb-ml44", "hyb-fn512",
         "slh128s", "slh128f", "slh256s", "slh256f"]


def rd(name):
    p = os.path.join(DATA, name)
    return pd.read_csv(p) if os.path.exists(p) else None


def save(fig, name):
    fig.savefig(os.path.join(OUT, name))
    plt.close(fig)
    print("wrote", name)


# ============================================================ small multiples
def small_multiples(data_name, value_col, value_from, ylabel, name, log=True):
    """One panel per uniform algorithm; faint Ed reference + size budgets."""
    df = rd(data_name)
    curves = {}
    for raw, g in df.groupby(df.columns[0]):
        c = fs.canon(raw)
        curves[c] = g
    ncol, nrow = 5, 2
    fig, axes = plt.subplots(nrow, ncol, figsize=(6.6, 3.05),
                             sharex=True, sharey=True)
    ed = curves.get("ed")
    budgets = [(4, "#888888", (0, (4, 3))), (16, "#bbbbbb", (0, (1, 3)))]
    for i, c in enumerate(UNIFORM):
        ax = axes.flat[i]
        g = curves.get(c)
        # budget reference lines
        if value_col == "size":
            for kib, col, ls in budgets:
                ax.axhline(kib, color=col, lw=0.8, ls=ls, zorder=0)
        # Ed reference (skip on Ed panel)
        if c != "ed" and ed is not None:
            xe, ye = value_from(ed)
            fs.ed_reference(ax, xe, ye)
        if g is not None:
            x, y = value_from(g)
            ax.plot(x, y, color=fs.FAMILY_COLOR[fs.FAMILY[c]], lw=1.6,
                    marker="o", ms=2.6, zorder=3)
        ax.set_title(fs.LONG[c], fontsize=7.6,
                     color=fs.FAMILY_COLOR[fs.FAMILY[c]], fontweight="bold")
        if log:
            ax.set_yscale("log")
        ax.tick_params(labelsize=6.4, length=2)
    for ax in axes[-1]:
        ax.set_xlabel("attenuation depth  n", fontsize=7.8)
    for ax in axes[:, 0]:
        ax.set_ylabel(ylabel, fontsize=7.8)
    fig.subplots_adjust(hspace=0.42, wspace=0.14, left=0.085,
                        right=0.985, top=0.90, bottom=0.16)
    save(fig, name)


def size_values(g):
    g = g.sort_values("n")
    return g.n.to_numpy(float), g.sealed_bytes.to_numpy(float) / 1024.0


def lat_values(g):
    g = g[g.phase == "verify_chain"].sort_values("n")
    return g.n.to_numpy(float), g.median_ns.to_numpy(float) / 1000.0


small_multiples("e55_token_size.csv", "size", size_values,
                "sealed size (KiB)", "size_vs_n.png")
small_multiples("e55_latency.csv", "lat", lat_values,
                "verify latency (\u00b5s)", "full_latency.png")


# ============================================================ verify (horizontal)
def verify_figure():
    sp = rd("formal_verify_slopes.csv")
    sp["ck"] = sp.alg.map(fs.canon)
    pv = sp.pivot_table(index="ck", columns="tag", values="verify_us_per_sig")
    pv = pv.reindex(ALL12)
    y = np.arange(len(ALL12)); h = 0.38
    fig, (a, b) = plt.subplots(1, 2, figsize=(6.6, 3.7), sharey=True,
                               gridspec_kw={"width_ratios": [1.25, 1]})
    a.barh(y + h/2, pv.avx2, height=h, color=fs.BUILD_COLOR["avx2"],
            label="AVX2")
    a.barh(y - h/2, pv.portable, height=h, color=fs.BUILD_COLOR["portable"],
            label="portable")
    a.set_xscale("log")
    a.set_yticks(y); a.set_yticklabels([fs.LONG[c] for c in ALL12], fontsize=7)
    a.invert_yaxis()
    a.set_xlabel("whole-chain verify (\u00b5s per signature, log)", fontsize=7.8)
    a.set_title("(a) AVX2 vs portable clean C", fontsize=8.6)
    a.legend(fontsize=7, loc="upper right")
    ratio = pv.portable / pv.avx2
    b.barh(y, ratio, height=0.6, color="#7A5195")
    b.axvline(1.0, color="black", lw=0.9, ls="--")
    b.set_xlabel("portable time / AVX2 time", fontsize=7.8)
    b.set_title("(b) portable penalty", fontsize=8.6)
    for yi, v in zip(y, ratio):
        b.text(v + 0.03, yi, f"{v:.2f}", va="center", fontsize=6.4)
    b.set_xlim(0, ratio.max() * 1.18)
    fig.subplots_adjust(left=0.20, right=0.98, top=0.90, bottom=0.13, wspace=0.08)
    save(fig, "verify_avx2_portable.png")


verify_figure()


# ============================================================ sign phases (horiz)
def sign_figure():
    ph = rd("formal_phases_n2.csv")
    ph["ck"] = ph.alg.map(fs.canon)
    y = np.arange(len(ALL12)); h = 0.38
    fig, (a, b) = plt.subplots(1, 2, figsize=(6.6, 3.9), sharey=True)
    for ax, op, title in [(a, "append_hop", "(a) append one hop (keygen+sign)"),
                          (b, "seal", "(b) seal (final signature)")]:
        d = ph[ph.op == op].pivot_table(index="ck", columns="tag",
                                        values="median").reindex(ALL12)
        ax.barh(y + h/2, d.avx2, height=h, color=fs.BUILD_COLOR["avx2"],
                label="AVX2")
        ax.barh(y - h/2, d.portable, height=h, color=fs.BUILD_COLOR["portable"],
                label="portable")
        ax.set_xscale("log")
        ax.set_xlabel("median time at n=2 (\u00b5s, log)", fontsize=7.6)
        ax.set_title(title, fontsize=8.4)
    a.set_yticks(y); a.set_yticklabels([fs.LONG[c] for c in ALL12], fontsize=7)
    a.invert_yaxis()
    a.legend(fontsize=7, loc="upper right")
    fig.subplots_adjust(left=0.20, right=0.985, top=0.90, bottom=0.13, wspace=0.10)
    save(fig, "sign_phases.png")


sign_figure()


# ============================================================ FN length
def fnlen_figure():
    fl = rd("formal_fnlen.csv")
    groups = ["fn512", "hyb-fn512", "fn1024"]
    pos = np.arange(len(groups))
    fig, ax = plt.subplots(figsize=(6.6, 3.7))
    for i, c in enumerate(groups):
        for t, off in [("avx2", -0.18), ("portable", 0.18)]:
            r = fl[(fl.alg.map(fs.canon) == c) & (fl.tag == t)].iloc[0]
            col = fs.BUILD_COLOR[t]
            ax.boxplot([[r.sig_min, r.sig_q1, r.sig_median, r.sig_q3, r.sig_max]],
                       positions=[i + off], widths=0.32, showfliers=False,
                       patch_artist=True,
                       boxprops=dict(color=col, facecolor=col,
                                     alpha=0.8 if t == "avx2" else 0.45),
                       medianprops=dict(color="black", lw=1.1),
                       whiskerprops=dict(color=col), capprops=dict(color=col))
            ax.text(i + off, r.sig_max + 14, f"max {int(r.sig_max)}",
                    ha="center", fontsize=6.2, color=col)
    ax.hlines(666, -0.5, 1.5, color=OI_RED, ls="--", lw=1.2)
    ax.text(0.5, 706, "FIPS 206 cap 666 (level I)", color=OI_RED,
            fontsize=7.4, ha="center")
    ax.hlines(1280, 1.5, 2.5, color=OI_RED, ls="--", lw=1.2)
    ax.text(2.0, 1352, "FIPS 206 cap 1280 (level V)", color=OI_RED,
            fontsize=7.4, ha="center")
    ax.annotate("pre-FIPS build occasionally\nemits 1281 B (1 B over cap)",
                xy=(2.18, 1281), xytext=(1.05, 1090), color="darkred",
                fontsize=6.8, ha="left",
                arrowprops=dict(arrowstyle="->", color="darkred", lw=0.9))
    ax.set_xticks(pos)
    ax.set_xticklabels(["FN-DSA-512", "Hyb Ed+FN512\n(outer FN-512)",
                        "FN-DSA-1024"], fontsize=7.4)
    ax.set_ylim(595, 1375)
    ax.set_ylabel("FN-DSA signature length (bytes)", fontsize=8)
    ax.set_title("Variable signature length over 51 sealed tokens vs FIPS 206 cap",
                 fontsize=9)
    ax.legend(handles=[Patch(facecolor=fs.BUILD_COLOR["avx2"], label="AVX2"),
                       Patch(facecolor=fs.BUILD_COLOR["portable"], alpha=.5,
                             label="portable"),
                       plt.Line2D([0], [0], color=OI_RED, ls="--",
                                  label="FIPS 206 cap")],
              fontsize=7, loc="upper left")
    fig.subplots_adjust(left=0.11, right=0.98, top=0.89, bottom=0.13)
    save(fig, "fnlen.png")


OI_RED = "#C0392B"
fnlen_figure()


# ============================================================ pregen (horizontal)
def pregen_figure():
    pg = rd("e6_pregen.csv")
    pg["ck"] = pg.alg.map(fs.canon)
    g = pg.groupby(["ck", "phase"]).ns.median().unstack() / 1000.0
    g = g.reindex(ALL12)
    y = np.arange(len(ALL12)); h = 0.26
    fig, ax = plt.subplots(figsize=(6.6, 4.0))
    ax.barh(y + h, g.keygen, height=h, color=fs.PHASE_COLOR["keygen"],
            label="key generation (offline)")
    ax.barh(y, g.append_sign, height=h, color=fs.PHASE_COLOR["sign"],
            label="online append, pre-minted key (sign only)")
    ax.barh(y - h, g.append_realtime, height=h, color=fs.PHASE_COLOR["realtime"],
            label="naive online append (keygen+sign)")
    ax.set_xscale("log")
    ax.set_yticks(y); ax.set_yticklabels([fs.LONG[c] for c in ALL12], fontsize=7)
    ax.invert_yaxis()
    ax.set_xlabel("time per attenuation hop (\u00b5s, log)", fontsize=8)
    ax.set_title("Offline pre-generation removes keygen from the online path",
                 fontsize=9)
    ax.legend(fontsize=7, loc="upper right")
    for c in ("fn512", "fn1024", "hyb-fn512"):
        yi = ALL12.index(c)
        saving = 100 * (1 - g.loc[c, "append_sign"] / g.loc[c, "append_realtime"])
        ax.text(g.loc[c, "append_realtime"] * 1.12, yi - h,
                f"\u2212{saving:.0f}% online", va="center", fontsize=6.8,
                color="#1B5E3B", fontweight="bold")
    fig.subplots_adjust(left=0.20, right=0.95, top=0.90, bottom=0.11)
    save(fig, "pregen.png")


pregen_figure()


# ============================================================ hybrid size/latency
def hybrid_figures():
    sz = rd("e55_hybrid_size.csv")
    lt = rd("e55_hybrid_latency.csv")
    order = ["ed", "ml44", "fn512", "hyb-ml44", "hyb-fn512"]
    sz["ck"] = sz.alg.map(fs.canon)
    lt["ck"] = lt.alg.map(fs.canon)
    # ---- size
    fig, ax = plt.subplots(figsize=(6.6, 3.3))
    for c in order:
        g = sz[sz.ck == c].sort_values("n")
        emph = c.startswith("hyb")
        ax.plot(g.n, g.sealed_bytes / 1024.0,
                color=fs.FAMILY_COLOR[fs.FAMILY[c]],
                lw=2.4 if emph else 1.4,
                ls="-" if emph else (0, (4, 3)),
                marker="o" if emph else None, ms=3.2, zorder=4 if emph else 2)
        x_end = g.n.iloc[-1]; y_end = g.sealed_bytes.iloc[-1] / 1024.0
        if c in ("ed", "hyb-ml44", "hyb-fn512"):
            fs.direct_label(ax, x_end, y_end, fs.SHORT[c],
                            fs.FAMILY_COLOR[fs.FAMILY[c]], dx=4,
                            weight="bold" if emph else None)
    for kib in (4, 8, 16):
        ax.axhline(kib, color="#cccccc", lw=0.8, ls=(0, (1, 3)))
    ax.set_yscale("log"); ax.set_xlim(-0.5, 23.5)
    ax.set_xlabel("attenuation depth  n", fontsize=8)
    ax.set_ylabel("sealed size (KiB, log)", fontsize=8)
    ax.set_title("Hybrid tokens: classical fallback with a post-quantum signature",
                 fontsize=9)
    fig.subplots_adjust(left=0.10, right=0.86, top=0.89, bottom=0.14)
    save(fig, "hybrid_size.png")
    # ---- latency
    fig, ax = plt.subplots(figsize=(6.6, 3.3))
    for c in order:
        g = lt[(lt.ck == c) & (lt.phase == "verify_chain")].sort_values("n")
        emph = c.startswith("hyb")
        ax.plot(g.n, g.median_ns / 1000.0,
                color=fs.FAMILY_COLOR[fs.FAMILY[c]],
                lw=2.4 if emph else 1.4,
                ls="-" if emph else (0, (4, 3)),
                marker="o" if emph else None, ms=3.2, zorder=4 if emph else 2)
        if c in ("ed", "hyb-ml44", "hyb-fn512"):
            fs.direct_label(ax, g.n.iloc[-1], g.median_ns.iloc[-1] / 1000.0,
                            fs.SHORT[c], fs.FAMILY_COLOR[fs.FAMILY[c]], dx=4,
                            weight="bold" if emph else None)
    ax.set_xlim(-0.5, 23.5)
    ax.set_xlabel("attenuation depth  n", fontsize=8)
    ax.set_ylabel("whole-chain verification (\u00b5s)", fontsize=8)
    ax.set_title("Hybrid verification latency", fontsize=9)
    fig.subplots_adjust(left=0.10, right=0.86, top=0.89, bottom=0.14)
    save(fig, "hybrid_latency.png")


hybrid_figures()


# ============================================================ mixed chains
def mixed_figure():
    m = rd("e55_mixed.csv")
    # n=5 and n=10 sealed size per root/atten combination (data span n=0..10)
    combos = m[["root", "atten"]].drop_duplicates()
    labels, sizes5, sizes10 = [], [], []
    uniform_root = {"Mldsa87": "ml87", "Slhdsa128s": "slh128s",
                    "Slhdsa256s": "slh256s"}
    for _, rcb in combos.iterrows():
        root, att = rcb.root, rcb.atten
        g = m[(m.root == root) & (m.atten == att)]
        s5 = g[g.n == 5].sealed_bytes.iloc[0] / 1024.0
        s10 = g[g.n == 10].sealed_bytes.iloc[0] / 1024.0
        labels.append(f"{fs.SHORT[uniform_root[root]]}\nroot + {fs.SHORT[fs.canon(att)]} hops")
        sizes5.append(s5); sizes10.append(s10)
    x = np.arange(len(labels)); w = 0.38
    fig, ax = plt.subplots(figsize=(6.6, 3.4))
    ax.bar(x - w/2, sizes5, w, color="#9C6BA6", label="n = 5")
    ax.bar(x + w/2, sizes10, w, color=fs.FAMILY_COLOR["mix"], label="n = 10")
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=7)
    ax.set_ylabel("sealed size (KiB)", fontsize=8)
    ax.set_title("Mixed chains: strong post-quantum root, lightweight hops",
                 fontsize=9)
    ax.legend(fontsize=7.5, loc="upper left")
    for xi, v in zip(x - w/2, sizes5):
        ax.text(xi, v + 0.4, f"{v:.1f}", ha="center", fontsize=6.6)
    for xi, v in zip(x + w/2, sizes10):
        ax.text(xi, v + 0.4, f"{v:.1f}", ha="center", fontsize=6.6)
    fig.subplots_adjust(left=0.10, right=0.98, top=0.89, bottom=0.16)
    save(fig, "mixed_chains.png")


mixed_figure()


# ============================================================ fidelity heatmap
def fidelity_figure():
    fid = rd("e6_fidelity.csv")
    checks = ["f1_seal_atten_verify", "f2_datalog_write_denied",
              "f3_unsealed_roundtrip", "f4_key_bytes_roundtrip",
              "f5_wrong_root_rejected", "f6_tamper_rejected",
              "f7_third_party_pq", "f8_third_party_wrong_key",
              "f9_hybrid_cross_combo"]
    clab = ["seal+atten\n+verify", "Datalog\nwrite denied", "unsealed\nroundtrip",
            "key byte\nroundtrip", "wrong root\nrejected", "tamper\nrejected",
            "3rd-party\nPQ block", "3rd-party\nwrong key", "hybrid cross-\ncombo"]
    mat = pd.DataFrame(index=ALL12, columns=checks)
    for _, r in fid.iterrows():
        mat.loc[fs.canon(r.alg), r.check] = 1 if r.result == "PASS" else 0
    M = mat.to_numpy(float)
    fig, ax = plt.subplots(figsize=(6.6, 4.7))
    for i, c in enumerate(ALL12):
        for j in range(len(checks)):
            v = M[i, j]
            if np.isnan(v):
                face, txt, tc = "white", "\u2013", "#999999"
            elif v == 1:
                face, txt, tc = "#2E8B57", "\u2713", "white"
            else:
                face, txt, tc = "#C0392B", "\u2715", "white"
            ax.add_patch(plt.Rectangle((j, i), 1, 1, facecolor=face,
                                       edgecolor="white", lw=1.0))
            ax.text(j + 0.5, i + 0.5, txt, ha="center", va="center",
                    color=tc, fontsize=9, fontweight="bold")
    ax.set_xlim(0, len(checks)); ax.set_ylim(len(ALL12), 0)
    ax.set_xticks(np.arange(len(checks)) + 0.5)
    ax.set_xticklabels(clab, fontsize=6.6)
    ax.set_yticks(np.arange(len(ALL12)) + 0.5)
    ax.set_yticklabels([fs.LONG[c] for c in ALL12], fontsize=7)
    ax.tick_params(length=0); ax.xaxis.tick_top()
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title("Functional fidelity & security-binding matrix (all applicable checks pass)",
                 fontsize=8.8, pad=30)
    ax.legend(handles=[Patch(facecolor="#2E8B57", label="PASS"),
                       Patch(facecolor="white", label="N/A (f9 hybrid-only)")],
              fontsize=7, loc="lower center", bbox_to_anchor=(0.5, -0.10), ncol=2)
    fig.subplots_adjust(left=0.19, right=0.98, top=0.86, bottom=0.10)
    save(fig, "fidelity.png")


fidelity_figure()
print("\nall micro figures ->", OUT)
