#!/usr/bin/env python3
"""
E5-5 full-algorithm calibration / validation.

Takes the REAL measurements from the integrated biscuit-rust build for all
nine PQ parameter sets + Ed25519 and checks the SINGLE calibrated overhead
model recovered in E5-4 (OV_AUTH / OV_ATTEN / WRAP, fitted only on Ed25519 and
ML-DSA-44) against every other algorithm WITHOUT retuning any constant. Small
residuals are reported honestly (SLH tiny keys change a length-prefix byte;
FN-DSA signatures are variable-length).

Inputs : data/e55_token_size.csv, data/e55_latency.csv, data/algostats.csv
Outputs: data/e55_calibration.json, data/capacity_e55.csv,
         figures/fig9_full_size.png, figures/fig10_full_latency.png
"""
import csv, os, json, copy
from collections import defaultdict
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from model_tokens import field_len, load_stats, PQ_ORDER, BUDGETS
a0, a1 = 0, 1

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
FIG = os.path.join(HERE, "figures")
os.makedirs(FIG, exist_ok=True)

NICE = {"ed25519": "Ed25519", "mldsa44": "ML-DSA-44", "mldsa65": "ML-DSA-65",
        "mldsa87": "ML-DSA-87", "fndsa512": "FN-DSA-512", "fndsa1024": "FN-DSA-1024",
        "slhdsa128s": "SLH-DSA-128s", "slhdsa128f": "SLH-DSA-128f",
        "slhdsa256s": "SLH-DSA-256s", "slhdsa256f": "SLH-DSA-256f"}
COLOR = {"ed25519": "#7f7f7f", "mldsa44": "#1f77b4", "mldsa65": "#2c8bd4",
         "mldsa87": "#0b4f8a", "fndsa512": "#2ca02c", "fndsa1024": "#177a17",
         "slhdsa128s": "#ff7f0e", "slhdsa128f": "#ff9d3d",
         "slhdsa256s": "#d62728", "slhdsa256f": "#e8650a"}
MARKER = {"ed25519": "s", "mldsa44": "o", "mldsa65": "o", "mldsa87": "o",
          "fndsa512": "^", "fndsa1024": "^",
          "slhdsa128s": "D", "slhdsa128f": "D", "slhdsa256s": "D", "slhdsa256f": "D"}

OV_AUTH = {"ed": 47, "pq": 50}
OV_ATTEN = {"ed": 25, "pq": 29}
WRAP = {"ed": 2, "pq": 3}


def cls_of(v):
    return "ed" if v == "ed25519" else "pq"


def cal_size(st, v, n, mode):
    s = st[v]
    c = cls_of(v)
    auth = field_len(1 + s["pk"]) + field_len(s["sig"]) + OV_AUTH[c]
    att = field_len(1 + s["pk"]) + field_len(s["sig"]) + OV_ATTEN[c]
    if mode == "sealed":
        proof = field_len(s["sig"])
    else:
        mat = s["sk"] if c == "ed" else s["sk"] + s["pk"]
        proof = field_len(mat)
    return auth + n * att + proof + WRAP[c]


def read_csv(name):
    with open(os.path.join(DATA, name), newline="") as f:
        return list(csv.DictReader(f))


def main():
    st_cap = load_stats()                       # FN sig = FIPS padded cap
    st = copy.deepcopy(st_cap)
    for v in ("fndsa512", "fndsa1024"):          # real tokens store measured sigs
        st[v]["sig"] = int(st[v]["sig_measured"])

    # ---- real size curves ----
    real = defaultdict(lambda: {"sealed": {}, "unsealed": {}})
    for r in read_csv("e55_token_size.csv"):
        v = r["alg"].lower()
        n = int(r["n"])
        real[v]["sealed"][n] = int(r["sealed_bytes"])
        real[v]["unsealed"][n] = int(r["unsealed_bytes"])

    size_fits, validation, capacities = {}, {}, {}
    for v in PQ_ORDER:
        if v not in real:
            continue
        size_fits[v] = {}
        validation[v] = {}
        for mode in ("sealed", "unsealed"):
            curve = real[v][mode]
            ns = np.array(sorted(curve))
            ys = np.array([curve[n] for n in ns])
            slope, ic = np.polyfit(ns, ys, 1)
            pred = slope * ns + ic
            r2 = 1 - np.sum((ys - pred) ** 2) / np.sum((ys - ys.mean()) ** 2)
            size_fits[v][mode] = dict(intercept=round(float(ic), 1),
                                      slope=round(float(slope), 2),
                                      r2=round(float(r2), 6))
            m = "sealed" if mode == "sealed" else "attenuable"
            errs = [(cal_size(st, v, n, m) - curve[n]) / curve[n] * 100
                    for n in ns]
            validation[v][mode] = dict(
                model_max_abs_pct=round(max(abs(x) for x in errs), 3),
                model_mean_abs_pct=round(float(np.mean(np.abs(errs))), 3),
                model_signed_pct_at_n2=round(errs[list(ns).index(2)] if 2 in ns else errs[0], 3))
        caps = {}
        curve = real[v]["sealed"]
        for b in BUDGETS:
            fit = [n for n in range(0, 21) if curve[n] <= b]
            caps[b] = max(fit) if fit else -1
        capacities[v] = caps

    # ---- real latency ----
    lat = defaultdict(dict)
    reps = {}
    for r in read_csv("e55_latency.csv"):
        v = r["alg"].lower()
        lat[(v, r["phase"])][int(r["n"])] = int(r["median_ns"]) / 1e3
        reps[v] = int(r["reps"])
    verify_fit, phase_n2 = {}, {}
    for v in PQ_ORDER:
        d = lat[(v, "verify_chain")]
        if d:
            ns = np.array(sorted(d)); ys = np.array([d[n] for n in ns])
            slope, ic = np.polyfit(ns, ys, 1)
            pred = slope * ns + ic
            r2 = 1 - np.sum((ys - pred) ** 2) / np.sum((ys - ys.mean()) ** 2)
            verify_fit[v] = dict(slope_us_per_sig=round(float(slope), 2),
                                 intercept_us=round(float(ic), 2),
                                 r2=round(float(r2), 5), nmax=int(ns.max()))
        phase_n2[v] = {ph: round(lat[(v, ph)].get(2, float("nan")), 2)
                       for ph in ("authority_build", "append_hop", "seal",
                                  "verify_chain", "authorize")}

    # ---- persist ----
    with open(os.path.join(DATA, "capacity_e55.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["variant", "budget_bytes", "max_atten_blocks_real"])
        for v in PQ_ORDER:
            if v in capacities:
                for b in BUDGETS:
                    w.writerow([v, b, capacities[v][b]])
    out = dict(
        note="Single E5-4 overhead model (fitted on Ed/ML-DSA-44 only) validated "
             "against all algorithms without retuning; FN uses measured variable "
             "signature length, FIPS cap kept for conservative capacity.",
        size_fits=size_fits, model_validation_pct=validation,
        real_capacity_sealed=capacities,
        verify_chain_fit=verify_fit, phase_median_us_at_n2=phase_n2, reps=reps,
        fn_sig=dict(measured={v: st[v]["sig"] for v in ("fndsa512", "fndsa1024")},
                    fips_cap={v: st_cap[v]["sig"] for v in ("fndsa512", "fndsa1024")}))
    with open(os.path.join(DATA, "e55_calibration.json"), "w") as f:
        json.dump(out, f, indent=2)

    # ============ fig 9: real size across all algorithms ============
    fig, axes = plt.subplots(1, 2, figsize=(12, 5.2))
    ax = axes[a0]
    hlab = []
    for v in PQ_ORDER:
        if v not in real:
            continue
        d = real[v]["sealed"]
        ns = sorted(d)
        line, = ax.plot(ns, [d[n] / 1024 for n in ns], lw=1.5,
                        color=COLOR[v], label=NICE[v])
        pick = [n for n in ns if n in (0, 5, 10, 20)]
        ax.plot(pick, [d[n] / 1024 for n in pick], linestyle="none",
                marker=MARKER[v], ms=4.5, color=COLOR[v])
        hlab.append(line)
    for b in BUDGETS:
        ax.axhline(b / 1024, color="black", ls="--", lw=0.8, alpha=0.4)
        ax.text(20.4, b / 1024, f"{b//1024} KiB", va="center", ha="left",
                fontsize=8, color="0.30")
    ax.set_yscale("log")
    ax.set_xlim(-0.6, 24.4)
    ax.set_ylim(bottom=0.15)
    ax.set_xlabel("number of attenuation blocks  n")
    ax.set_ylabel("sealed token size (KiB, log)")
    ax.set_title("Real sealed token size, all parameter sets", fontsize=10.5)
    ax.grid(which="both", alpha=0.25)
    ax.legend(handles=hlab, loc="upper center", bbox_to_anchor=(0.5, -0.15),
              ncol=5, fontsize=7.7, frameon=False, columnspacing=0.9,
              handlelength=1.6, handletextpad=0.4)

    ax = axes[a1]
    labels = [NICE[v] for v in PQ_ORDER if v in validation]
    sealed_err = [validation[v]["sealed"]["model_max_abs_pct"] for v in PQ_ORDER if v in validation]
    unsealed_err = [validation[v]["unsealed"]["model_max_abs_pct"] for v in PQ_ORDER if v in validation]
    x = np.arange(len(labels)); w = 0.4
    ax.bar(x - w/2, sealed_err, w, label="sealed", color="#1f77b4")
    ax.bar(x + w/2, unsealed_err, w, label="unsealed", color="#ff7f0e")
    ax.set_xticks(x); ax.set_xticklabels(labels, rotation=40, ha="right", fontsize=7.5)
    ax.set_ylabel("max |model error| over n=0..20  (%)")
    ax.set_title("One calibrated model predicts all schemes (no refit)", fontsize=10.5)
    ax.set_ylim(0, max(0.25, max(sealed_err + unsealed_err) * 1.40))
    ax.grid(axis="y", alpha=0.3); ax.legend(fontsize=8, loc="upper right")
    fig.tight_layout()
    fig.subplots_adjust(bottom=0.20)
    fig.savefig(os.path.join(FIG, "fig9_full_size.png"), dpi=200)
    plt.close(fig)

    # ============ fig 10: whole-chain verification latency (single panel, linear) ============
    fig, ax = plt.subplots(1, 1, figsize=(7.4, 4.7))
    for v in PQ_ORDER:
        d = lat[(v, "verify_chain")]
        if not d:
            continue
        ns = np.array(sorted(d)); ys = np.array([d[n] for n in ns])
        ax.plot(ns, ys, linestyle="-", lw=1.8, color=COLOR[v], label=NICE[v])
        pick = {0, 1, 2} if ns.max() <= 2 else {0, 5, 10, 20}
        mp = [int(n) for n in ns if int(n) in pick]
        ax.plot(mp, [d[n] for n in mp], linestyle="none", marker=MARKER[v],
                ms=5.5, color=COLOR[v])
    ax.set_xlabel("number of attenuation blocks  n")
    ax.set_ylabel("whole-chain verification time (µs)")
    ax.set_title("Whole-chain verification latency (real tokens)", fontsize=11)
    ax.set_ylim(bottom=0)
    ax.set_xlim(-0.6, 20.8)
    ax.grid(alpha=0.3)
    ax.legend(fontsize=8, ncol=2, loc="upper right", framealpha=0.95)
    ax.margins(x=0.02)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "fig10_full_latency.png"), dpi=200)
    plt.close(fig)

    # ---- console ----
    print("== real linear fits (sealed): intercept / slope(bytes per hop) / R2 ==")
    for v in PQ_ORDER:
        if v in size_fits:
            f = size_fits[v]["sealed"]
            print(f"  {NICE[v]:14s} {f['intercept']:9.1f} / {f['slope']:9.2f} / {f['r2']}")
    print("\n== single-model validation, max abs % (sealed / unsealed) ==")
    for v in PQ_ORDER:
        if v in validation:
            print(f"  {NICE[v]:14s} {validation[v]['sealed']['model_max_abs_pct']:6.3f} / "
                  f"{validation[v]['unsealed']['model_max_abs_pct']:6.3f}")
    print("\n== real sealed capacity (max attenuation blocks) ==")
    for v in PQ_ORDER:
        if v in capacities:
            c = capacities[v]
            print(f"  {NICE[v]:14s} 4KiB={c[4096]:3d}  8KiB={c[8192]:3d}  16KiB={c[16384]:3d}")
    print("\n== verify-chain slope µs/signature (R2, nmax) ==")
    for v in PQ_ORDER:
        if v in verify_fit:
            f = verify_fit[v]
            print(f"  {NICE[v]:14s} {f['slope_us_per_sig']:9.2f}  R2={f['r2']} nmax={f['nmax']}")
    print("\n== per-phase median µs at n=2 ==")
    for v in PQ_ORDER:
        if v in phase_n2:
            p = phase_n2[v]
            print(f"  {NICE[v]:14s} auth={p['authority_build']:10.1f} append={p['append_hop']:10.1f} "
                  f"seal={p['seal']:10.1f} verify={p['verify_chain']:9.1f} authz={p['authorize']:8.1f}")
    print("\nwrote e55_calibration.json, capacity_e55.csv, fig9, fig10")


if __name__ == "__main__":
    main()
