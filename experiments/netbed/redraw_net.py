#!/usr/bin/env python3
"""Redraw the network-layer figures (E-N1..E-N5) for the CN manuscript.

Reads the frozen aggregated CSVs produced by analyze_net.py (no new
measurements) and redraws with the unified semantic style.  Each panel keeps
only the curves that carry the argument; end-of-line labels (with tiny leader
lines where the curves converge) replace the dense legend.
"""
import os, sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import figstyle as fs

HERE = os.path.dirname(os.path.abspath(__file__))
AN = os.path.join(HERE, "analysis")
OUT = os.path.join(HERE, "figs")
os.makedirs(OUT, exist_ok=True)
fs.setup()

# network profile name -> canonical key; only the argument curves are kept.
KEEP = ["ed25519", "mldsa87", "fndsa512", "slhdsa128f", "mix-mldsa87-fndsa512"]
# vertical (points) de-collision offsets for end labels, per panel family
DY = {"ed": 16, "ml87": 2, "fn512": -12, "slh128f": -24, "mix": 28}


def rd(name):
    p = os.path.join(AN, name)
    return pd.read_csv(p) if os.path.exists(p) else None


def save(fig, name):
    fig.savefig(os.path.join(OUT, name))
    plt.close(fig)
    print("wrote", name)


def end_label(ax, x, y, ckey, dy=None, leader=True, dx=5):
    col = fs.FAMILY_COLOR[fs.FAMILY[ckey]]
    bold = fs.FAMILY[ckey] == "mix"
    ax.annotate(fs.SHORT[ckey], xy=(x, y),
                xytext=(dx, 0 if dy is None else dy),
                textcoords="offset points", ha="left", va="center",
                fontsize=7.4, color=col, fontweight="bold" if bold else None,
                clip_on=False,
                arrowprops=(dict(arrowstyle="-", color=col, lw=0.5, alpha=0.7)
                            if leader and dy else None),
                zorder=6)


def draw_curves_unused():
    pass


# ============================================================ netfig1 latency
def netfig1():
    s = rd("en1_summary.csv")
    rtts = sorted(s.rtt_ms.unique())
    fig, axes = plt.subplots(1, 2, figsize=(6.8, 3.2), sharex=True)
    for ax, mode, title in [(axes[0], "ka", "(a) keep-alive (single RTT)"),
                            (axes[1], "new", "(b) new connection (two RTT)")]:
        d = s[(s.n == 20) & (s["mode"] == mode)]
        for prof in KEEP:
            ckey = fs.canon(prof)
            g = d[d.profile == prof].sort_values("rtt_ms")
            if g.empty:
                continue
            col = fs.FAMILY_COLOR[fs.FAMILY[ckey]]
            emph = fs.FAMILY[ckey] == "mix"
            yms = g.total_p50_us / 1000.0
            ax.plot(g.rtt_ms, yms, color=col, lw=2.3 if emph else 1.5,
                    marker=("o" if emph else None), ms=3.4,
                    zorder=5 if emph else 3)
            # label at the smallest RTT, where server-cost differences separate
            r0 = g.iloc[0]
            ax.annotate(fs.SHORT[ckey], xy=(r0.rtt_ms, yms.iloc[0]),
                        xytext=(5, 0), textcoords="offset points",
                        ha="left", va="center", fontsize=7.1, color=col,
                        fontweight="bold" if emph else None, clip_on=False,
                        bbox=dict(boxstyle="round,pad=0.2", fc="white",
                                  ec="none", alpha=0.82), zorder=6)
        ax.set_xscale("symlog", linthresh=1)
        ax.set_yscale("log")
        ax.set_xlabel("round-trip time  \u03c4  (ms)", fontsize=8)
        ax.set_title(title, fontsize=8.8)
        ax.set_xlim(-1.5, rtts[-1] * 2.4)
    axes[0].set_ylabel("median transaction latency (ms)", fontsize=8)
    fig.subplots_adjust(left=0.09, right=0.86, top=0.88, bottom=0.16, wspace=0.12)
    save(fig, "netfig1_latency_rtt.png")


netfig1()


# ============================================================ netfig2 rho
def netfig2():
    s = rd("en1_summary.csv")
    rtts = sorted(s.rtt_ms.unique())
    d = s[(s.n == 20) & (s["mode"] == "ka")]
    fig, ax = plt.subplots(figsize=(6.4, 3.3))
    for prof in KEEP:
        ckey = fs.canon(prof)
        g = d[d.profile == prof].sort_values("rtt_ms")
        if g.empty:
            continue
        col = fs.FAMILY_COLOR[fs.FAMILY[ckey]]
        emph = fs.FAMILY[ckey] == "mix"
        ax.plot(g.rtt_ms, g.rho, color=col, lw=2.3 if emph else 1.6,
                marker="o", ms=3.2, zorder=5 if emph else 3)
        # label at a mid RTT (~20ms) where rho is maximally separated; nudge
        # the three mid curves apart vertically
        DY2 = {"ed": 0, "ml87": 14, "fn512": 0, "slh128f": 0,
               "mix-ml87-fn512": -14}
        rL = g.loc[(g.rtt_ms - 20).abs().idxmin()]
        ax.annotate(fs.SHORT[ckey], xy=(rL.rtt_ms, rL.rho),
                    xytext=(5, DY2[ckey]), textcoords="offset points",
                    ha="left", va="center", fontsize=7.1, color=col,
                    fontweight="bold" if emph else None, clip_on=False,
                    bbox=dict(boxstyle="round,pad=0.2", fc="white",
                              ec="none", alpha=0.85), zorder=6,
                    arrowprops=dict(arrowstyle="-", color=col, lw=0.5,
                                    alpha=0.6))
    ax.axhline(0.5, color="gray", ls="--", lw=1)
    ax.set_xscale("symlog", linthresh=1)
    ax.set_xlim(-1.5, rtts[-1] * 1.15)
    ax.set_xticks([0, 1, 5, 20, 50, 100])
    ax.set_xlabel("round-trip time  \u03c4  (ms)", fontsize=8)
    ax.set_ylabel(r"server-cost share  $\rho=t_{srv}/L$", fontsize=8)
    ax.set_title("Server-cost share, keep-alive, n=20", fontsize=9.2)
    fig.subplots_adjust(left=0.10, right=0.98, top=0.89, bottom=0.15)
    save(fig, "netfig2_rho_rtt.png")


netfig2()


# ============================================================ netfig3 loss
def netfig3():
    s = rd("en2_loss.csv")
    d = s[(s.n == 20) & (s["mode"] == "new")]
    losses = sorted(d.loss_pct.unique())
    fig, axes = plt.subplots(1, 2, figsize=(6.8, 3.2), sharex=True)
    DY3 = {
        "p50_us": {"ed": 0, "ml87": 0, "fn512": -12, "slh128f": 0,
                   "mix-ml87-fn512": 12},
        "p99_us": {"ed": 0, "ml87": 15, "fn512": -15, "slh128f": 0,
                   "mix-ml87-fn512": 0}}
    for ax, col_, title in [(axes[0], "p50_us", "(a) median latency"),
                            (axes[1], "p99_us", "(b) P99 tail latency")]:
        for prof in KEEP:
            ckey = fs.canon(prof)
            g = d[d.profile == prof].sort_values("loss_pct")
            if g.empty:
                continue
            c = fs.FAMILY_COLOR[fs.FAMILY[ckey]]
            emph = fs.FAMILY[ckey] == "mix"
            ax.plot(g.loss_pct, g[col_] / 1e3, color=c,
                    lw=2.3 if emph else 1.5,
                    marker=("o" if emph else None), ms=3.3,
                    zorder=5 if emph else 3)
            end_label(ax, g.loss_pct.iloc[-1], g[col_].iloc[-1] / 1e3, ckey,
                      dy=DY3[col_].get(ckey, 0))
        ax.set_xlabel("independent Bernoulli loss  p  (%)", fontsize=8)
        ax.set_title(title + ", RTT=20ms", fontsize=8.6)
        ax.set_xlim(-0.3, losses[-1] * 1.9)
    axes[0].set_ylabel("latency (ms)", fontsize=8)
    fig.subplots_adjust(left=0.09, right=0.85, top=0.88, bottom=0.16, wspace=0.12)
    save(fig, "netfig3_loss.png")


netfig3()


# ============================================================ netfig4 throughput
def netfig4():
    a = rd("en3_throughput.csv")
    d = a[a.n == 20]
    rtts = sorted(d.rtt_ms.unique())
    fig, axes = plt.subplots(1, len(rtts), figsize=(6.8, 2.9), sharey=True)
    DY4 = {"ed": 6, "ml87": -18, "fn512": -6, "slh128f": 0,
           "mix-ml87-fn512": 18}
    for ax, rtt in zip(axes, rtts):
        dd = d[d.rtt_ms == rtt]
        for prof in KEEP:
            ckey = fs.canon(prof)
            g = dd[dd.profile == prof].sort_values("conc")
            if g.empty:
                continue
            c = fs.FAMILY_COLOR[fs.FAMILY[ckey]]
            emph = fs.FAMILY[ckey] == "mix"
            ax.plot(g.conc, g.rps, color=c, lw=2.3 if emph else 1.5,
                    marker=("o" if emph else None), ms=3.3,
                    zorder=5 if emph else 3)
            # labels only de-collided where the curves converge (high RTT)
            dy = DY4.get(ckey, 0) if rtt >= rtts[-1] else 0
            end_label(ax, g.conc.iloc[-1], g.rps.iloc[-1], ckey, dy=dy,
                      leader=rtt >= rtts[-1])
        ax.set_xlabel("concurrent clients  c", fontsize=8)
        ax.set_title(f"RTT={int(rtt)} ms" if rtt else "RTT\u22480", fontsize=8.6)
        ax.set_xlim(0.8, dd.conc.max() * 1.25)
    axes[0].set_ylabel("aggregate throughput (req/s)", fontsize=8)
    fig.subplots_adjust(left=0.09, right=0.97, top=0.87, bottom=0.17, wspace=0.12)
    save(fig, "netfig4_throughput.png")


netfig4()


# ============================================================ netfig5 bandwidth
def netfig5():
    s = rd("en4_bandwidth.csv")
    fig, ax = plt.subplots(figsize=(6.2, 3.6))
    rate_style = {"1mbit": ("o", fs.OI["blue"], "1 Mbit/s"),
                  "46kbit": ("^", fs.OI["vermillion"], "46 kbit/s")}
    for rate, (mk, col, lab) in rate_style.items():
        g = s[s.rate == rate]
        ax.scatter(g.lpred_ms, g.p50_ms, marker=mk, s=34, color=col,
                   label=lab, zorder=4)
    lim = max(s.lpred_ms.max(), s.p50_ms.max()) * 1.08
    ax.plot([0, lim], [0, lim], color="gray", ls="--", lw=1, label="model y=x")
    ax.set_xlabel(r"predicted latency  $\tau+t_{srv}+8S/B$  (ms)", fontsize=8.4)
    ax.set_ylabel("measured median latency (ms)", fontsize=8.4)
    ax.set_title("Narrow-band transactions: wire model vs measurement", fontsize=9.2)
    ax.legend(fontsize=7.6, loc="upper left")
    fig.subplots_adjust(left=0.11, right=0.98, top=0.89, bottom=0.14)
    save(fig, "netfig5_bandwidth.png")


netfig5()
print("\nnetwork figures ->", OUT)
