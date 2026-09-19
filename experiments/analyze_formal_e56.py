#!/usr/bin/env python3
"""E5-6 formal single-threaded analysis: median+IQR, AVX2 vs portable clean C,
verify slope, five-phase n=2, FN-DSA variable signature length vs FIPS 206 cap.

Inputs (data/): e56_latency_{avx2,portable}.csv (raw samples, long format),
                e56_size_{avx2,portable}.csv, e56_fnlen_{avx2,portable}.csv
Outputs: figures/fig14_formal_verify.png, fig15_formal_sign.png,
         fig16_fnlen.png, data/formal_*.csv, data/e56_formal_summary.json
"""
import json, os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
FIG = os.path.join(HERE, "figures")
os.makedirs(FIG, exist_ok=True)

ORDER = ["Ed25519", "Mldsa44", "Mldsa65", "Mldsa87", "Fndsa512", "Fndsa1024",
         "HybridEdMldsa44", "HybridEdFndsa512",
         "Slhdsa128s", "Slhdsa128f", "Slhdsa256s", "Slhdsa256f"]
LABEL = {
    "Ed25519": "Ed25519", "Mldsa44": "ML-DSA-44", "Mldsa65": "ML-DSA-65",
    "Mldsa87": "ML-DSA-87", "Fndsa512": "FN-DSA-512", "Fndsa1024": "FN-DSA-1024",
    "HybridEdMldsa44": "Hyb Ed+ML44", "HybridEdFndsa512": "Hyb Ed+FN512",
    "Slhdsa128s": "SLH-128s", "Slhdsa128f": "SLH-128f",
    "Slhdsa256s": "SLH-256s", "Slhdsa256f": "SLH-256f",
}
TAGS = ["avx2", "portable"]
# PQClean-measured typical FN-DSA signature lengths (anchor, matches E5 calibration)
FN_TYPICAL = {"Fndsa512": 653, "Fndsa1024": 1269, "HybridEdFndsa512": 653}
FN_CAP = {"Fndsa512": 666, "Fndsa1024": 1280, "HybridEdFndsa512": 666}

lat = pd.concat([pd.read_csv(os.path.join(DATA, f"e56_latency_{t}.csv")).assign(tag=t)
                 for t in TAGS], ignore_index=True)
lat["us"] = lat["ns"] / 1000.0

def q(p):
    return lambda x: np.percentile(x, p)

agg = (lat.groupby(["tag", "alg", "op", "n"])["us"]
       .agg(reps="count", pmin="min", q1=q(25), median="median",
            q3=q(75), pmax="max").reset_index())
agg["iqr"] = agg["q3"] - agg["q1"]

# ---------- verify-chain slope (us per signature) ----------
slope_rows = []
for (tag, alg), g in lat[lat.op == "verify_chain"].groupby(["tag", "alg"]):
    m = g.groupby("n")["us"].median().reset_index()
    x = m["n"].to_numpy(dtype=float)
    # number of signatures verified for sealed token with n attenuation blocks ~ n+2
    s = x + 2.0
    y = m["us"].to_numpy(dtype=float)
    A = np.vstack([s, np.ones_like(s)]).T
    (k, b), res, *_ = np.linalg.lstsq(A, y, rcond=None)
    yhat = k * s + b
    ss_res = float(((y - yhat) ** 2).sum())
    ss_tot = float(((y - y.mean()) ** 2).sum())
    r2 = 1 - ss_res / ss_tot if ss_tot > 0 else 1.0
    slope_rows.append(dict(tag=tag, alg=alg, verify_us_per_sig=k, intercept_us=b, r2=r2))
slope = pd.DataFrame(slope_rows)
slope.to_csv(os.path.join(DATA, "formal_verify_slopes.csv"), index=False)

# ---------- five phases at n=2 (median + IQR) ----------
phases = ["authority_build", "append_hop", "seal", "verify_n2", "authorize"]
ph = agg[(agg.n == 2) & (agg.op.isin(phases))].copy()
ph["op"] = pd.Categorical(ph["op"], categories=phases, ordered=True)
ph = ph.sort_values(["op", "tag"])
ph.to_csv(os.path.join(DATA, "formal_phases_n2.csv"), index=False)

# ---------- speedup portable/avx2 ----------
sp = slope.pivot(index="alg", columns="tag", values="verify_us_per_sig").reindex(ORDER)
sp["verify_speedup_portable_over_avx2"] = sp["portable"] / sp["avx2"]
phm = ph.pivot_table(index=["alg", "op"], columns="tag", values="median").reset_index()
phm["ratio_portable_over_avx2"] = phm["portable"] / phm["avx2"]
phm.to_csv(os.path.join(DATA, "formal_speedup.csv"), index=False)

# ---------- deterministic size check (non-FN identical across builds) ----------
sz_a = pd.read_csv(os.path.join(DATA, "e56_size_avx2.csv"))
sz_p = pd.read_csv(os.path.join(DATA, "e56_size_portable.csv"))
fn_algs = set(FN_TYPICAL)
det_a = sz_a[~sz_a.alg.isin(fn_algs)].reset_index(drop=True)
det_p = sz_p[~sz_p.alg.isin(fn_algs)].reset_index(drop=True)
identical = det_a.equals(det_p)
szfit_rows = []
for alg in ORDER:
    g = sz_a[sz_a.alg == alg]
    x = g.n.to_numpy(float); y = g.sealed_bytes.to_numpy(float)
    k, b = np.polyfit(x, y, 1)
    szfit_rows.append(dict(alg=alg, sealed_intercept=b, sealed_per_hop=k))
szfit = pd.DataFrame(szfit_rows)
szfit.to_csv(os.path.join(DATA, "formal_size_fit.csv"), index=False)

# ---------- FN signature-length distribution (51 trials) ----------
fnrows = []
for t in TAGS:
    f = pd.read_csv(os.path.join(DATA, f"e56_fnlen_{t}.csv"))
    for alg, g in f.groupby("alg"):
        s = g.sealed_n0.to_numpy(float)
        typical = FN_TYPICAL[alg]
        sig = s - (np.median(s) - typical)   # shift so median anchors PQClean typical
        fnrows.append(dict(tag=t, alg=alg, n=len(s),
                           sig_min=sig.min(), sig_q1=np.percentile(sig, 25),
                           sig_median=np.median(sig), sig_q3=np.percentile(sig, 75),
                           sig_max=sig.max(), cap=FN_CAP[alg], typical=typical,
                           headroom_to_cap=FN_CAP[alg] - sig.max()))
fnlen = pd.DataFrame(fnrows)
fnlen.to_csv(os.path.join(DATA, "formal_fnlen.csv"), index=False)

# ================= FIG 14: verify slope AVX2 vs portable =================
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 4.6))
x = np.arange(len(ORDER)); w = 0.4
va = sp["avx2"].to_numpy(); vp = sp["portable"].to_numpy()
b1 = ax1.bar(x - w/2, va, w, label="AVX2 PQClean", color="#1f5fa8", edgecolor="black", linewidth=.4)
b2 = ax1.bar(x + w/2, vp, w, label="portable clean C", color="#e8a13a",
             edgecolor="black", linewidth=.4, hatch="//")
ax1.set_yscale("log"); ax1.set_xticks(x); ax1.set_xticklabels([LABEL[a] for a in ORDER],
             rotation=40, ha="right", fontsize=8)
ax1.set_ylabel(r"whole-chain verify ($\mu$s per signature, log)")
ax1.set_title("(a) Verification cost: AVX2 vs portable (pinned core)")
ax1.grid(alpha=.3, axis="y", which="both"); ax1.legend(fontsize=9)
for b, v in list(zip(b1, va)) + list(zip(b2, vp)):
    ax1.text(b.get_x()+b.get_width()/2, v*1.08, f"{v:.0f}" if v >= 100 else f"{v:.1f}",
             ha="center", va="bottom", fontsize=6.3, rotation=90)

ratio = sp["verify_speedup_portable_over_avx2"].to_numpy()
bars = ax2.bar(x, ratio, 0.62, color="#7a5195", edgecolor="black", linewidth=.4)
ax2.axhline(1.0, color="black", lw=1, ls="--")
ax2.set_xticks(x); ax2.set_xticklabels([LABEL[a] for a in ORDER], rotation=40, ha="right", fontsize=8)
ax2.set_ylabel(r"portable time / AVX2 time ($\times$)")
ax2.set_title("(b) Portable penalty on verification (>1 = AVX2 faster)")
ax2.grid(alpha=.3, axis="y")
for b, v in zip(bars, ratio):
    ax2.text(b.get_x()+b.get_width()/2, v+0.02, f"{v:.2f}", ha="center", va="bottom", fontsize=7)
# headroom so the topmost value labels clear the upper spine (log / linear)
ax1.set_ylim(bottom=ax1.get_ylim()[0], top=2600)
ax2.set_ylim(0, 3.40)
fig.tight_layout(); fig.savefig(os.path.join(FIG, "fig14_formal_verify.png"), dpi=200); plt.close(fig)

# ================= FIG 15: authority(keygen+sign via append) & seal ==========
fig, axes = plt.subplots(1, 2, figsize=(13, 4.8))
for ax, op, title in [
    (axes[0], "append_hop", "(a) Append one attenuation hop (fresh keygen + sign)"),
    (axes[1], "seal", "(b) Seal (final signature only)")]:
    dp = ph[(ph.op == op) & (ph.tag == "portable")].set_index("alg").reindex(ORDER)
    da = ph[(ph.op == op) & (ph.tag == "avx2")].set_index("alg").reindex(ORDER)
    mp = dp["median"].to_numpy(float); ma = da["median"].to_numpy(float)
    ea = np.vstack([ma-da["q1"].to_numpy(float), da["q3"].to_numpy(float)-ma])
    ep = np.vstack([mp-dp["q1"].to_numpy(float), dp["q3"].to_numpy(float)-mp])
    ax.bar(x-w/2, ma, w, yerr=ea, capsize=2.5, color="#1f5fa8", edgecolor="black",
           linewidth=.4, label="AVX2", error_kw=dict(lw=.7))
    ax.bar(x+w/2, mp, w, yerr=ep, capsize=2.5, color="#e8a13a", edgecolor="black",
           linewidth=.4, hatch="//", label="portable", error_kw=dict(lw=.7))
    ax.set_yscale("log"); ax.set_xticks(x)
    ax.set_xticklabels([LABEL[a] for a in ORDER], rotation=40, ha="right", fontsize=8)
    ax.set_ylabel(r"median time at $n=2$ ($\mu$s, log)")
    ax.set_title(title); ax.grid(alpha=.3, axis="y", which="both"); ax.legend(fontsize=9)
for _ax in axes:  # headroom above the tallest (log-scale) bars / error caps
    _lo, _hi = _ax.get_ylim(); _ax.set_ylim(_lo, _hi * 1.5)
fig.tight_layout(); fig.savefig(os.path.join(FIG, "fig15_formal_sign.png"), dpi=200); plt.close(fig)

# ================= FIG 16: FN signature length vs FIPS cap =================
fig, ax = plt.subplots(figsize=(9.4, 5.2))
fns = ["Fndsa512", "HybridEdFndsa512", "Fndsa1024"]
pos = np.arange(len(fns))
for i, alg in enumerate(fns):
    for t in TAGS:
        off = -0.18 if t == "avx2" else 0.18
        col = "#1f5fa8" if t == "avx2" else "#e8a13a"
        r = fnlen[(fnlen.alg == alg) & (fnlen.tag == t)].iloc[0]
        ax.boxplot([[r.sig_min, r.sig_q1, r.sig_median, r.sig_q3, r.sig_max]],
                   positions=[i+off], widths=0.32, showfliers=False, patch_artist=True,
                   boxprops=dict(color=col, facecolor=col, alpha=.75 if t=="avx2" else .40),
                   medianprops=dict(color="black", lw=1.2),
                   whiskerprops=dict(color=col), capprops=dict(color=col))
        _cap = FN_CAP[alg]
        _dy_hi = 16 if _cap <= 666 else 12
        ax.text(i+off, r.sig_max+_dy_hi, f"max {int(r.sig_max)}", ha="center", fontsize=6.6, color=col)
        ax.text(i+off, r.sig_median-32, f"med {int(r.sig_median)}", ha="center", fontsize=6.2, color=col)
# FIPS 206 padded caps: 666 B (level I) for FN-512 and the hybrid outer FN-512;
# 1280 B (level V) for FN-1024. Cap labels sit in the empty band above each group.
ax.hlines(666, -0.5, 1.5, color="red", ls="--", lw=1.4)
ax.text(0.5, 716, "FIPS 206 cap 666 (level I)", color="red", fontsize=8.5,
        va="center", ha="center")
ax.hlines(1280, 1.5, 2.5, color="red", ls="--", lw=1.4)
ax.text(2.0, 1334, "FIPS 206 cap 1280 (level V)", color="red", fontsize=8.5,
        va="center", ha="center")
ax.annotate("pre-FIPS pqcrypto-falcon 0.4.1 occasionally emits 1281 B\n(1 B above the FIPS 206 padded cap; level-I FN-512 stays within 666)",
            xy=(2+0.18, 1281), xytext=(-0.46, 1078), color="darkred", fontsize=8.2,
            ha="left", va="center",
            arrowprops=dict(arrowstyle="->", color="darkred", lw=1.0))
ax.set_xticks(pos); ax.set_xticklabels(["FN-DSA-512", "Hyb Ed+FN-512\n(outer FN-512)", "FN-DSA-1024"])
ax.set_ylim(595, 1380)
ax.set_ylabel("FN-DSA signature length (bytes)")
ax.set_title("FN-DSA variable signature length over 51 sealed tokens vs FIPS 206 padded cap")
ax.grid(alpha=.3, axis="y")
from matplotlib.patches import Patch
ax.legend(handles=[Patch(facecolor="#1f5fa8", alpha=.75, label="AVX2"),
                   Patch(facecolor="#e8a13a", alpha=.40, label="portable clean C"),
                   plt.Line2D([0],[0], color="red", ls="--", label="FIPS 206 padded cap")],
          fontsize=9, loc="upper left")
fig.tight_layout(); fig.savefig(os.path.join(FIG, "fig16_fnlen.png"), dpi=200); plt.close(fig)

# ---------- console + json summary ----------
pd.set_option("display.width", 200)
print("== verify slope (us/sig) ==")
print(sp.round(2).to_string())
print("\n== deterministic (non-FN) size identical across builds? ==", identical)
print("\n== sealed(n) fit (intercept / per-hop) ==")
print(szfit.round(1).to_string(index=False))
print("\n== FN signature length (median / max / cap / headroom) ==")
print(fnlen[["tag","alg","sig_median","sig_max","cap","headroom_to_cap"]].round(1).to_string(index=False))
print("\n== phase portable/avx2 ratios (n=2) ==")
pv = phm.pivot(index="alg", columns="op", values="ratio_portable_over_avx2").reindex(ORDER)
print(pv.round(2).to_string())

summary = {
    "verify_us_per_sig": {t: {a: float(sp.loc[a, t]) for a in ORDER} for t in TAGS},
    "verify_speedup_portable_over_avx2": {a: float(sp.loc[a, "verify_speedup_portable_over_avx2"]) for a in ORDER},
    "phases_n2_median_us": {t: {op: {a: float(ph[(ph.tag==t)&(ph.op==op)].set_index("alg").reindex([a])["median"].iloc[0]) for a in ORDER} for op in phases} for t in TAGS},
    "deterministic_size_identical_across_builds": bool(identical),
    "sealed_fit": {r.alg: [float(r.sealed_intercept), float(r.sealed_per_hop)] for _, r in szfit.iterrows()},
    "fn_signature_len": fnlen.to_dict(orient="records"),
    "fips206_status": "FN-DSA still a draft (IPD late 2025); final expected late 2026/early 2027 per NIST roadmap & IETF COSE/LAMPS drafts, accessed 2026-09",
}
with open(os.path.join(DATA, "e56_formal_summary.json"), "w") as fh:
    json.dump(summary, fh, indent=2)
print("\nwrote fig14/15/16 + formal_*.csv + e56_formal_summary.json")
