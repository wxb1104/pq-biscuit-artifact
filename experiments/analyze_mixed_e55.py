#!/usr/bin/env python3
"""
E5-5 mixed-chain analysis.

Real mixed-algorithm Biscuit chains (conservative root A, lightweight
attenuation B) are compared with uniform-A chains using the stock public API.
The measurements confirm the analytic structure:
  mixed_sealed(n) = uniform_A_sealed(0) + n * per_hop(B)
i.e. the root scheme costs a constant two signatures while every attenuation
hop (and the asymptotic slope / verification cost) follows the lighter scheme.

Inputs : data/e55_mixed.csv, data/e55_token_size.csv, data/e55_latency.csv
Outputs: data/e55_mixed_summary.json, figures/fig11_mixed_chains.png
"""
import csv, os, json
from collections import defaultdict
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
a0, a1 = 0, 1

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
FIG = os.path.join(HERE, "figures")

NICE = {"mldsa44": "ML-DSA-44", "mldsa65": "ML-DSA-65", "mldsa87": "ML-DSA-87",
        "fndsa512": "FN-DSA-512", "fndsa1024": "FN-DSA-1024",
        "slhdsa128s": "SLH-DSA-128s", "slhdsa128f": "SLH-DSA-128f",
        "slhdsa256s": "SLH-DSA-256s", "slhdsa256f": "SLH-DSA-256f"}
ROOT_COLOR = {"mldsa87": "#0b4f8a", "slhdsa256s": "#d62728", "slhdsa128s": "#ff7f0e"}


def read_csv(name):
    with open(os.path.join(DATA, name), newline="") as f:
        return list(csv.DictReader(f))


def main():
    # mixed measurements
    size = defaultdict(dict)
    ver = defaultdict(dict)
    for r in read_csv("e55_mixed.csv"):
        key = (r["root"].lower(), r["atten"].lower())
        n = int(r["n"])
        if r["sealed_bytes"]:
            size[key][n] = int(r["sealed_bytes"])
        if r["verify_median_us"]:
            ver[key][n] = float(r["verify_median_us"])

    # uniform reference curves
    usize = defaultdict(dict)
    for r in read_csv("e55_token_size.csv"):
        usize[r["alg"].lower()][int(r["n"])] = int(r["sealed_bytes"])
    uver = defaultdict(dict)
    for r in read_csv("e55_latency.csv"):
        if r["phase"] == "verify_chain":
            uver[r["alg"].lower()][int(r["n"])] = float(r["median_ns"]) / 1e3
    # linear fits so slow schemes (SLH only measured to n=2) can be extrapolated
    uver_fit = {k: np.polyfit(np.array(sorted(d)),
                              np.array([d[n] for n in sorted(d)]), 1)
                for k, d in uver.items()}

    summary = {}
    for key, d in size.items():
        a, b = key
        ns = np.array(sorted(d)); ys = np.array([d[n] for n in ns])
        slope, ic = np.polyfit(ns, ys, 1)
        r2 = 1 - np.sum((ys - (slope * ns + ic)) ** 2) / np.sum((ys - ys.mean()) ** 2)
        vns = np.array(sorted(ver[key])); vys = np.array([ver[key][n] for n in vns])
        vslope, vic = np.polyfit(vns, vys, 1)
        vr2 = 1 - np.sum((vys - (vslope * vns + vic)) ** 2) / np.sum((vys - vys.mean()) ** 2)
        # savings at n = 10 vs a uniform root-A chain
        mixed_s10 = d[10]
        uni_s10 = usize[a][10]
        mixed_v10 = ver[key][10]
        uni_v10_measured = uver[a].get(10)
        uni_v10 = uni_v10_measured if uni_v10_measured is not None \
            else float(np.polyval(uver_fit[a], 10))
        note = "measured" if uni_v10_measured is not None else "extrapolated"
        summary[f"{a}>{b}"] = dict(
            root=a, atten=b,
            size_intercept=round(float(ic), 1), size_per_hop=round(float(slope), 2),
            size_r2=round(float(r2), 6),
            uniform_root_n0=usize[a][0],
            verify_intercept_us=round(float(vic), 2),
            verify_per_hop_us=round(float(vslope), 2), verify_r2=round(float(vr2), 5),
            n10=dict(
                mixed_bytes=mixed_s10, uniform_root_bytes=uni_s10,
                size_saving_pct=round(100 * (1 - mixed_s10 / uni_s10), 1),
                mixed_verify_us=round(mixed_v10, 2),
                uniform_root_verify_us=round(uni_v10, 2),
                uniform_root_verify_basis=note,
                verify_saving_pct=round(100 * (1 - mixed_v10 / uni_v10), 1)))
    with open(os.path.join(DATA, "e55_mixed_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    # ---------- fig 11 ----------
    shown = [("slhdsa256s", "fndsa512"), ("mldsa87", "fndsa512"),
             ("slhdsa128s", "mldsa44")]
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.6))
    ax = axes[a0]
    for key in shown:
        a, b = key
        c = ROOT_COLOR[a]
        d = size[key]; ns = sorted(d)
        lab = f"{NICE[a]} root → {NICE[b]} hops (mixed)"
        ax.plot(ns, [d[n] / 1024 for n in ns], "-o", ms=4, lw=1.9, color=c, label=lab)
        un = usize[a]
        ax.plot(sorted(un), [un[n] / 1024 for n in sorted(un)], "--",
                lw=1.3, color=c, alpha=0.55,
                label=f"uniform {NICE[a]} (reference)")
    for bud in (4096, 8192, 16384):
        ax.axhline(bud / 1024, color="black", ls=":", lw=0.7, alpha=0.4)
    ax.set_xlabel("number of attenuation blocks  n")
    ax.set_ylabel("sealed token size (KiB)")
    ax.set_title("Mixed chains: constant strong-root cost,\nlight per-hop growth", fontsize=10.5)
    ax.grid(alpha=0.25); ax.legend(fontsize=7.6, loc="upper left")

    ax = axes[a1]
    for key in shown:
        a, b = key
        c = ROOT_COLOR[a]
        d = ver[key]; ns = sorted(d)
        ax.plot(ns, [d[n] for n in ns], "-o", ms=5, lw=1.9, color=c,
                label=f"{NICE[a]} → {NICE[b]} (mixed)")
        xx = np.arange(0, 11)
        ax.plot(xx, np.polyval(uver_fit[a], xx), "--", lw=1.3, color=c, alpha=0.55,
                label=f"uniform {NICE[a]} (fit)")
    ax.set_xlabel("number of attenuation blocks  n")
    ax.set_ylabel("whole-chain verification time (µs)")
    ax.set_title("Mixed chains: strong root verified once,\ncheap hops dominate", fontsize=10.5)
    ax.grid(alpha=0.25); ax.legend(fontsize=7.6, loc="upper left")
    axes[a0].margins(y=0.12); axes[a1].margins(y=0.12)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "fig11_mixed_chains.png"), dpi=200)
    plt.close(fig)

    print("== mixed-chain fits (sealed bytes: intercept / per-hop / R2) ==")
    for k, v in summary.items():
        print(f"  {k:24s} {v['size_intercept']:9.1f} / {v['size_per_hop']:8.2f} / {v['size_r2']}")
    print("\n== n=10 savings vs uniform root scheme ==")
    for k, v in summary.items():
        z = v["n10"]
        print(f"  {k:24s} size {z['mixed_bytes']:7d} vs {z['uniform_root_bytes']:7d} B "
              f"(-{z['size_saving_pct']:4.1f}%) | verify {z['mixed_verify_us']:7.1f} vs "
              f"{z['uniform_root_verify_us']:7.1f} µs (-{z['verify_saving_pct']:4.1f}%)")
    print("\nwrote e55_mixed_summary.json, fig11_mixed_chains.png")


if __name__ == "__main__":
    main()
