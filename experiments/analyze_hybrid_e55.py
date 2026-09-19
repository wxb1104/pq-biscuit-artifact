#!/usr/bin/env python3
"""E5-5 hybrid combiner analysis: real-system size/latency overhead of the
labelled strong-nesting hybrids vs their Ed25519 / ML-DSA-44 / FN-DSA-512
component baselines. Reads e55_hybrid_{size,latency}.csv, writes a JSON summary
and fig12 (size) / fig13 (latency)."""
import csv, json, os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

DATA = os.path.join(os.path.dirname(__file__), "data")
FIG = os.path.join(os.path.dirname(__file__), "figures")
os.makedirs(FIG, exist_ok=True)

ORDER = ["Ed25519", "Mldsa44", "Fndsa512", "HybridEdMldsa44", "HybridEdFndsa512"]
LABEL = {
    "Ed25519": "Ed25519 (classical)",
    "Mldsa44": "ML-DSA-44 (PQ)",
    "Fndsa512": "FN-DSA-512 (PQ)",
    "HybridEdMldsa44": "Hybrid Ed+ML-DSA-44",
    "HybridEdFndsa512": "Hybrid Ed+FN-DSA-512",
}
COLOR = {
    "Ed25519": "#7f7f7f", "Mldsa44": "#1f77b4", "Fndsa512": "#2ca02c",
    "HybridEdMldsa44": "#d62728", "HybridEdFndsa512": "#ff7f0e",
}
BUDGETS = [4096, 8192, 16384]


def read_size():
    d = {a: {"n": [], "unsealed": [], "sealed": []} for a in ORDER}
    with open(os.path.join(DATA, "e55_hybrid_size.csv")) as f:
        for r in csv.DictReader(f):
            if r["alg"] not in d:
                continue
            d[r["alg"]]["n"].append(int(r["n"]))
            d[r["alg"]]["unsealed"].append(int(r["unsealed_bytes"]))
            d[r["alg"]]["sealed"].append(int(r["sealed_bytes"]))
    return d


def linfit(x, y):
    x = np.asarray(x, float); y = np.asarray(y, float)
    slope, intercept = np.polyfit(x, y, 1)
    yhat = slope * x + intercept
    ss_res = float(np.sum((y - yhat) ** 2)); ss_tot = float(np.sum((y - y.mean()) ** 2))
    r2 = 1 - ss_res / ss_tot if ss_tot else 1.0
    return float(intercept), float(slope), r2


def main():
    size = read_size()
    summary = {}
    print("== sealed(n) = intercept + slope*n ==")
    for a in ORDER:
        si, ss, r2s = linfit(size[a]["n"], size[a]["sealed"])
        ui, us, r2u = linfit(size[a]["n"], size[a]["unsealed"])
        cap = {}
        for B in BUDGETS:
            # largest n with sealed <= B (n=0 intercept already > B -> -1)
            ok = [n for n, b in zip(size[a]["n"], size[a]["sealed"]) if b <= B]
            cap[f"{B//1024}KiB"] = max(ok) if ok else -1
        summary[a] = dict(sealed_intercept=round(si, 1), sealed_per_hop=round(ss, 1),
                          sealed_r2=round(r2s, 6), unsealed_intercept=round(ui, 1),
                          unsealed_per_hop=round(us, 1), unsealed_r2=round(r2u, 6),
                          capacity=cap)
        print(f"{a:>18}: intercept={si:8.1f} per_hop={ss:7.1f} R2={r2s:.6f} cap={cap}")

    # overhead of hybrid over its PQ component (deterministic bytes)
    print("\n== hybrid sealed overhead vs pure PQ component ==")
    for h, pq in [("HybridEdMldsa44", "Mldsa44"), ("HybridEdFndsa512", "Fndsa512")]:
        hi, hs, _ = linfit(size[h]["n"], size[h]["sealed"])
        pi, ps, _ = linfit(size[pq]["n"], size[pq]["sealed"])
        di, dsl = hi - pi, hs - ps
        summary[h]["delta_intercept_vs_pq"] = round(di, 1)
        summary[h]["delta_per_hop_vs_pq"] = round(dsl, 1)
        print(f"{h:>18}: dIntercept={di:6.1f} B  dPerHop={dsl:6.1f} B "
              f"(theory ~160 + ~96 n: +64B inner sig per signature, +32B Ed pk per nextKey)")

    # ---- latency ----
    lat = {a: {} for a in ORDER}
    with open(os.path.join(DATA, "e55_hybrid_latency.csv")) as f:
        for r in csv.DictReader(f):
            if r["alg"] not in lat:
                continue
            lat[r["alg"]].setdefault(r["phase"], {})[int(r["n"])] = int(r["median_ns"])

    print("\n== verify_chain slope (us per signature) ==")
    phases = ["authority_build", "append_hop", "seal", "verify_chain", "authorize"]
    for a in ORDER:
        ns = sorted(lat[a]["verify_chain"])
        x = np.asarray(ns, float)
        y = np.asarray([lat[a]["verify_chain"][n] for n in ns], float) / 1e3  # us
        vi, vs, r2 = linfit(x, y)
        summary[a].setdefault("latency_us", {})["verify_intercept_us"] = round(vi, 2)
        summary[a]["latency_us"]["verify_per_sig_us"] = round(vs, 2)
        summary[a]["latency_us"]["verify_r2"] = round(r2, 5)
        print(f"{a:>18}: {vs:7.2f} us/sig (intercept {vi:7.2f}, R2={r2:.5f})")

    print("\n== five-phase median at n=2 (us) ==")
    for a in ORDER:
        row = {ph: round(lat[a][ph][2] / 1e3, 2) for ph in phases}
        summary[a]["latency_us"]["n2_phases_us"] = row
        print(f"{a:>18}: " + " ".join(f"{ph.split('_')[0]}={v:8.2f}" for ph, v in zip(phases, [row[p] for p in phases])))

    with open(os.path.join(DATA, "e55_hybrid_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    # ---------- fig12: size ----------
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.6))
    for a in ORDER:
        ax1.plot(size[a]["n"], np.array(size[a]["sealed"]) / 1024,
                 marker="o", ms=3, lw=1.6, color=COLOR[a], label=LABEL[a])
    for B in BUDGETS:
        ax1.axhline(B / 1024, ls="--", lw=0.9, color="gray", alpha=0.7)
        ax1.text(20.2, B / 1024, f"{B//1024} KiB", va="center", fontsize=8, color="gray")
    ax1.set_xlabel("number of attenuation blocks $n$")
    ax1.set_ylabel("sealed token size (KiB)")
    ax1.set_title("(a) Sealed token size vs delegation length")
    ax1.grid(alpha=0.3); ax1.legend(fontsize=8, loc="upper left")

    # per-hop byte increment vs PQ component
    pairs = [("HybridEdMldsa44", "Mldsa44"), ("HybridEdFndsa512", "Fndsa512")]
    xpos = np.arange(2)
    d_inter = [summary[h]["delta_intercept_vs_pq"] for h, _ in pairs]
    d_hop = [summary[h]["delta_per_hop_vs_pq"] for h, _ in pairs]
    w = 0.35
    ax2.bar(xpos - w/2, d_inter, w, label="intercept overhead (B)", color="#9467bd")
    ax2.bar(xpos + w/2, d_hop, w, label="per-hop overhead (B)", color="#8c564b")
    for i, (di, dh) in enumerate(zip(d_inter, d_hop)):
        ax2.text(i - w/2, di + 2, f"{di:.0f}", ha="center", fontsize=8)
        ax2.text(i + w/2, dh + 2, f"{dh:.0f}", ha="center", fontsize=8)
    ax2.set_xticks(xpos); ax2.set_xticklabels(["Ed+ML-DSA-44\nvs ML-DSA-44",
                                               "Ed+FN-DSA-512\nvs FN-DSA-512"])
    ax2.set_ylabel("byte overhead")
    ax2.set_title("(b) Hybrid size overhead over PQ component")
    ax2.grid(alpha=0.3, axis="y")
    ax1.margins(y=0.12)
    ax2.set_ylim(0, max(max(d_inter), max(d_hop)) * 1.32)
    ax2.legend(fontsize=8, loc="lower center", bbox_to_anchor=(0.5, 0.83),
               ncol=2, frameon=False, columnspacing=0.8, handlelength=1.4)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "fig12_hybrid_size.png"), dpi=200)
    plt.close(fig)

    # ---------- fig13: latency ----------
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.6))
    algos = ORDER
    vslope = [summary[a]["latency_us"]["verify_per_sig_us"] for a in algos]
    bars = ax1.bar(range(len(algos)), vslope, color=[COLOR[a] for a in algos])
    ax1.set_xticks(range(len(algos))); ax1.set_xticklabels(
        [LABEL[a].replace(" (classical)", "").replace(" (PQ)", "") for a in algos],
        rotation=30, ha="right", fontsize=8)
    for b, v in zip(bars, vslope):
        ax1.text(b.get_x() + b.get_width()/2, v, f"{v:.1f}", ha="center",
                 va="bottom", fontsize=8)
    ax1.set_ylabel(r"whole-chain verify ($\mu$s per signature)")
    ax1.set_title("(a) Verification cost per signature")
    ax1.grid(alpha=0.3, axis="y")

    x = np.arange(len(phases)); w = 0.16
    ax2.set_yscale("log")
    for i, a in enumerate(algos):
        vals = [summary[a]["latency_us"]["n2_phases_us"][p] for p in phases]
        ax2.bar(x + (i - 2) * w, vals, w, color=COLOR[a], label=LABEL[a])
    ax2.set_xticks(x); ax2.set_xticklabels(
        ["authority", "append", "seal", "verify", "authorize"], fontsize=9)
    ax2.set_ylabel(r"median time at $n=2$ ($\mu$s, log)")
    ax2.set_title("(b) Five-phase latency")
    ax2.grid(alpha=0.3, which="both", axis="y"); ax2.legend(fontsize=7, ncol=2)
    ax1.set_ylim(0, max(vslope) * 1.16)   # room for the bar-top value labels
    ax2.margins(y=0.22)                   # lift the log-axis ceiling so tall bars are not clipped
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "fig13_hybrid_latency.png"), dpi=200)
    plt.close(fig)
    print("\nwrote fig12_hybrid_size.png and fig13_hybrid_latency.png")


if __name__ == "__main__":
    main()
