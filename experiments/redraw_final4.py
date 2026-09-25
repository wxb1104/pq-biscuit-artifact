#!/usr/bin/env python3
"""Final redraw of network figures (Fig.3-5) and deployment profiles (Fig.6).

Rules (scientific-visualization):
* no scheme text and no leader lines inside the plotting area;
* one external, colour-vision-safe legend per figure (colour + marker + ls);
* focus encoding: our Mixed profile is a heavy line with filled circles,
  Ed25519 is the black classical reference, comparisons are thinner;
* no background grid; Fig.4 uses a log y-axis so the SLH outlier no longer
  compresses the practical candidates.
"""
import os, sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import figstyle as fs
fs.setup()

NETAN = os.path.join(HERE, "netbed", "analysis")
NETOUT = os.path.join(HERE, "netbed", "figs_v2")
MICROOUT = os.path.join(HERE, "figures_v2")
DATA = os.path.join(HERE, "data")
for d in (NETOUT, MICROOUT):
    os.makedirs(d, exist_ok=True)

# network curves: profile -> (canon key, marker) ; order controls legend
NET = [("ed25519", "s"), ("mix-mldsa87-fndsa512", "o"),
       ("fndsa512", "^"), ("mldsa87", "D"), ("slhdsa128f", "v")]
NETLAB = {"ed25519": "Ed25519", "mix-mldsa87-fndsa512": "Mixed (ours)",
          "fndsa512": "FN-DSA-512", "mldsa87": "ML-DSA-87",
          "slhdsa128f": "SLH-DSA-128f"}


def style(ckey):
    fam = fs.FAMILY[ckey]
    col = fs.FAMILY_COLOR[fam]
    focus = fam == "mix"
    return dict(color=col, focus=focus,
                lw=2.6 if focus else 1.5,
                ls=("-") ,
                z=6 if focus else 3)


def bottom_legend(fig, pairs, ncol, bottom=0.20):
    handles, labels = [], []
    for line, lab in pairs:
        handles.append(line)
        labels.append(lab)
    fig.legend(handles, labels, loc="lower center", ncol=ncol, fontsize=8.2,
               frameon=False, bbox_to_anchor=(0.5, 0.0),
               handlelength=2.4, handletextpad=0.5, columnspacing=1.6,
               markerscale=1.1)


# ----------------------------------------------------------------- Fig.3
def fig3():
    s = pd.read_csv(os.path.join(NETAN, "en1_summary.csv"))
    rtts = sorted(s.rtt_ms.unique())
    fig, axes = plt.subplots(1, 2, figsize=(6.6, 3.0), sharex=True)
    pairs = []
    seen = set()
    for ax, mode, title in [(axes[0], "ka", "(a) keep-alive (single RTT)"),
                            (axes[1], "new", "(b) new connection (two RTT)")]:
        d = s[(s.n == 20) & (s["mode"] == mode)]
        for prof, mk in NET:
            ckey = fs.canon(prof)
            g = d[d.profile == prof].sort_values("rtt_ms")
            if g.empty:
                continue
            st = style(ckey)
            (ln,) = ax.plot(g.rtt_ms, g.total_p50_us / 1e3,
                            color=st["color"], lw=st["lw"], ls=st["ls"],
                            marker=mk, ms=4.2 if st["focus"] else 3.4,
                            markevery=2, zorder=st["z"])
            if prof not in seen:
                pairs.append((ln, NETLAB[prof]))
                seen.add(prof)
        ax.set_xscale("symlog", linthresh=1)
        ax.set_yscale("log")
        ax.set_xlabel("round-trip time  τ  (ms)", fontsize=8.6)
        ax.set_title(title, fontsize=9.2)
        ax.set_xlim(-1.5, rtts[-1] * 1.9)
    axes[0].set_ylabel("median transaction latency (ms)", fontsize=8.6)
    fig.subplots_adjust(left=0.09, right=0.98, top=0.88, bottom=0.24,
                        wspace=0.13)
    bottom_legend(fig, pairs, 5)
    fig.savefig(os.path.join(NETOUT, "netfig1_latency_rtt.png"),
                facecolor="white")
    plt.close(fig)
    print("wrote netfig1")


# ----------------------------------------------------------------- Fig.4
def fig4():
    s = pd.read_csv(os.path.join(NETAN, "en2_loss.csv"))
    d = s[(s.n == 20) & (s["mode"] == "new")]
    losses = sorted(d.loss_pct.unique())
    fig, axes = plt.subplots(1, 2, figsize=(6.6, 3.0), sharex=True)
    pairs, seen = [], set()
    for ax, col_, title in [(axes[0], "p50_us", "(a) median latency"),
                            (axes[1], "p99_us", "(b) P99 tail latency")]:
        for prof, mk in NET:
            ckey = fs.canon(prof)
            g = d[d.profile == prof].sort_values("loss_pct")
            if g.empty:
                continue
            st = style(ckey)
            (ln,) = ax.plot(g.loss_pct, g[col_] / 1e3,
                            color=st["color"], lw=st["lw"], ls=st["ls"],
                            marker=mk, ms=4.2 if st["focus"] else 3.4,
                            zorder=st["z"])
            if prof not in seen:
                pairs.append((ln, NETLAB[prof]))
                seen.add(prof)
        ax.set_yscale("log")
        ax.set_xlabel("independent Bernoulli loss  p  (%)", fontsize=8.6)
        ax.set_title(title + ", RTT = 20 ms", fontsize=9.0)
        ax.set_xlim(-0.3, losses[-1] * 1.5)
    axes[0].set_ylabel("latency (ms)", fontsize=8.6)
    fig.subplots_adjust(left=0.09, right=0.98, top=0.88, bottom=0.24,
                        wspace=0.13)
    bottom_legend(fig, pairs, 5)
    fig.savefig(os.path.join(NETOUT, "netfig3_loss.png"), facecolor="white")
    plt.close(fig)
    print("wrote netfig3")


# ----------------------------------------------------------------- Fig.5
def fig5():
    a = pd.read_csv(os.path.join(NETAN, "en3_throughput.csv"))
    d = a[a.n == 20]
    rtts = sorted(d.rtt_ms.unique())
    fig, axes = plt.subplots(1, len(rtts), figsize=(6.6, 2.8), sharey=True)
    pairs, seen = [], set()
    for ax, rtt in zip(axes, rtts):
        dd = d[d.rtt_ms == rtt]
        for prof, mk in NET:
            ckey = fs.canon(prof)
            g = dd[dd.profile == prof].sort_values("conc")
            if g.empty:
                continue
            st = style(ckey)
            (ln,) = ax.plot(g.conc, g.rps, color=st["color"], lw=st["lw"],
                            ls=st["ls"], marker=mk,
                            ms=4.0 if st["focus"] else 3.2, markevery=2,
                            zorder=st["z"])
            if prof not in seen:
                pairs.append((ln, NETLAB[prof]))
                seen.add(prof)
        ax.set_xlabel("concurrent clients  c", fontsize=8.6)
        ax.set_title(f"RTT = {int(rtt)} ms" if rtt else "RTT ≈ 0",
                     fontsize=9.0)
        ax.set_xlim(0.8, dd.conc.max() * 1.18)
    axes[0].set_ylabel("aggregate throughput (req/s)", fontsize=8.6)
    fig.subplots_adjust(left=0.09, right=0.98, top=0.87, bottom=0.26,
                        wspace=0.12)
    bottom_legend(fig, pairs, 5)
    fig.savefig(os.path.join(NETOUT, "netfig4_throughput.png"),
                facecolor="white")
    plt.close(fig)
    print("wrote netfig4")


# ----------------------------------------------------------------- Fig.6
def fig6():
    size = pd.read_csv(os.path.join(DATA, "e6_profiles_size.csv"))
    ver = (pd.read_csv(os.path.join(DATA, "e6_profiles_verify.csv"))
           .groupby(["profile", "n"])["ns"].median().reset_index())
    order = ["all-ed", "all-mldsa44", "all-fndsa512", "hybrid-ed-mldsa44",
             "hybrid-ed-fndsa512", "mixed-mldsa87-root-fn",
             "mixed-slh128s-root-fn"]
    rec = "mixed-mldsa87-root-fn"
    lab = {"all-ed": "Ed25519", "all-mldsa44": "ML-DSA-44",
           "all-fndsa512": "FN-DSA-512", "hybrid-ed-mldsa44": "Hyb Ed+ML44",
           "hybrid-ed-fndsa512": "Hyb Ed+FN512",
           "mixed-mldsa87-root-fn": "Mixed* (ours)",
           "mixed-slh128s-root-fn": "Mixed-SLH"}
    mk = {"all-ed": "s", "all-mldsa44": "D", "all-fndsa512": "^",
          "hybrid-ed-mldsa44": "P", "hybrid-ed-fndsa512": "X",
          "mixed-mldsa87-root-fn": "o", "mixed-slh128s-root-fn": "v"}
    fig, (axa, axb) = plt.subplots(1, 2, figsize=(6.6, 3.2))
    pairs = []
    for p in order:
        focus = p == rec
        col = fs.color_of(p)
        ds = size[size.profile == p].sort_values("n")
        (l1,) = axa.plot(ds.n, ds.size_bytes / 1024, color=col,
                         lw=2.7 if focus else 1.3,
                         marker=mk[p], ms=4.6 if focus else 3.0,
                         markevery=2, zorder=6 if focus else 2)
        dv = ver[ver.profile == p].sort_values("n")
        axb.plot(dv.n, dv.ns / 1000, color=col,
                 lw=2.7 if focus else 1.3, marker=mk[p],
                 ms=4.6 if focus else 3.0, markevery=2,
                 zorder=6 if focus else 2)
        pairs.append((l1, lab[p]))
    for b in (4, 8):
        axa.axhline(b, color="#9a9a9a", ls=":", lw=1.0, zorder=1)
    axa.text(12.0, 4.45, "4 KiB budget", fontsize=7, color="#808080")
    axa.text(12.0, 8.5, "8 KiB", fontsize=7, color="#808080")
    axa.set_yscale("log")
    axa.set_xlim(0, 24)
    axa.set_ylim(0.6, 120)
    axa.set_title("(a) sealed token size vs depth", fontsize=9.6)
    axa.set_xlabel("attenuation depth n", fontsize=8.6)
    axa.set_ylabel("sealed token size (KiB)", fontsize=8.6)
    axb.set_xlim(0, 24)
    axb.set_ylim(-60, 1950)
    axb.set_title("(b) verification latency vs depth (AVX2)", fontsize=9.6)
    axb.set_xlabel("attenuation depth n", fontsize=8.6)
    axb.set_ylabel("full-chain verification (µs)", fontsize=8.6)
    fig.subplots_adjust(left=0.09, right=0.98, top=0.90, bottom=0.26,
                        wspace=0.16)
    handles = [p[0] for p in pairs]
    labels = [p[1] for p in pairs]
    fig.legend(handles, labels, loc="lower center", ncol=4, fontsize=7.8,
               frameon=False, bbox_to_anchor=(0.5, 0.0),
               handlelength=2.0, handletextpad=0.4, columnspacing=1.2)
    fig.savefig(os.path.join(MICROOUT, "profiles.png"), facecolor="white")
    plt.close(fig)
    print("wrote profiles")


fig3()
fig4()
fig5()
fig6()
print("done")
