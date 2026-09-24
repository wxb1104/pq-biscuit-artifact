#!/usr/bin/env python3
"""Analysis for the Post-Quantum Biscuit network testbed (E-N1..E-N6).

Reads raw CSVs from experiments/data and the offline token manifest, recomputes
every reported statistic from the raw samples (no hard-coded numbers), and emits
summary CSVs + publication figures (no background grid, per journal style).

Stages missing from the data are skipped, so it is safe to run while E-N1 runs.

Usage: python3 analyze_net.py [--quick]
"""
import argparse, os, math, json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.abspath(os.path.join(HERE, "..", "data"))
FIGD = os.path.abspath(os.path.join(HERE, "figs"))
OUTD = os.path.abspath(os.path.join(HERE, "analysis"))
os.makedirs(FIGD, exist_ok=True)
os.makedirs(OUTD, exist_ok=True)

MSS = 1460
plt.rcParams.update({"font.size": 9, "axes.grid": False, "figure.dpi": 150,
                     "savefig.bbox": "tight", "axes.spines.top": False,
                     "axes.spines.right": False})

# representative profiles + display styling
REP = ["ed25519", "mldsa87", "fndsa512", "fndsa1024", "slhdsa128f",
       "hyb-ed-fndsa512", "mix-mldsa87-fndsa512"]
LABEL = {"ed25519": "Ed25519", "mldsa44": "ML-DSA-44", "mldsa65": "ML-DSA-65",
         "mldsa87": "ML-DSA-87", "fndsa512": "FN-DSA-512", "fndsa1024": "FN-DSA-1024",
         "slhdsa128s": "SLH-DSA-128s", "slhdsa128f": "SLH-DSA-128f",
         "slhdsa256s": "SLH-DSA-256s", "slhdsa256f": "SLH-DSA-256f",
         "hyb-ed-mldsa44": "Hybrid Ed+ML44", "hyb-ed-fndsa512": "Hybrid Ed+FN512",
         "mix-mldsa87-fndsa512": "Mixed ML87/FN512",
         "mix-slh256s-fndsa512": "Mixed SLH256s/FN512",
         "mix-mldsa87-mldsa44": "Mixed ML87/ML44"}
MARK = {"ed25519": "o", "mldsa87": "s", "fndsa512": "^", "fndsa1024": "D",
        "slhdsa128f": "v", "hyb-ed-fndsa512": "P", "mix-mldsa87-fndsa512": "X"}
COL = {"ed25519": "#1f77b4", "mldsa87": "#2ca02c", "fndsa512": "#d62728",
       "fndsa1024": "#9467bd", "slhdsa128f": "#ff7f0e",
       "hyb-ed-fndsa512": "#17becf", "mix-mldsa87-fndsa512": "#8c564b"}


def pct(x, qs=(50, 95, 99)):
    x = np.asarray(x, dtype=float)
    return tuple(np.percentile(x, qs) if len(x) else (np.nan,) * len(qs))


def boot_med_ci(x, B=2000, seed=0):
    x = np.asarray(x, dtype=float)
    if len(x) < 2:
        m = np.median(x) if len(x) else np.nan
        return m, m, m
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(x), size=(B, len(x)))
    meds = np.median(x[idx], axis=1)
    return np.median(x), np.percentile(meds, 2.5), np.percentile(meds, 97.5)


def linfit(x, y):
    x = np.asarray(x, float); y = np.asarray(y, float)
    if len(x) < 2:
        return np.nan, np.nan, np.nan
    A = np.vstack([x, np.ones_like(x)]).T
    m, b = np.linalg.lstsq(A, y, rcond=None)[0]
    yhat = m * x + b
    ss = np.sum((y - yhat) ** 2); st = np.sum((y - y.mean()) ** 2)
    r2 = 1 - ss / st if st > 0 else np.nan
    return m, b, r2


def load(name, **kw):
    p = os.path.join(DATA, name)
    return pd.read_csv(p, **kw) if os.path.exists(p) else None


def manifest_map():
    man = load(os.path.join("..", "netbed", "net_tokens_manifest.csv"))
    if man is None:
        man = load("net_tokens_manifest.csv")
    if man is None:
        return {}
    return {(r.profile, int(r.n)): (int(r.raw_b), int(r.b64_b)) for r in man.itertuples()}


# ---------------------------------------------------------------- E-N1
def analyze_en1(lat, man):
    en1all = lat[lat.exp == "en1"].copy()
    en1 = en1all[en1all.status == 200].copy()
    if en1.empty:
        print("[E-N1] no data"); return None
    rows = []
    keys = ["profile", "n", "mode", "rtt_ms"]
    for key, gall in en1all.groupby(keys):
        prof, n, mode, rtt = key
        g = gall[gall.status == 200]
        tot = g.total_ns.to_numpy(); ver = g.verify_ns.to_numpy()
        p50, p95, p99 = pct(tot); v50 = np.median(ver)
        m, lo, hi = boot_med_ci(tot, seed=hash((prof, n, mode, rtt)) % (2**31))
        nfail = int((gall.status != 200).sum())
        rows.append(dict(profile=prof, n=int(n), mode=mode, rtt_ms=rtt, samples=len(gall),
                         total_p50_us=p50/1e3, total_p95_us=p95/1e3, total_p99_us=p99/1e3,
                         tsrv_us=v50/1e3, rho=v50/p50,
                         p50_ci_lo_us=lo/1e3, p50_ci_hi_us=hi/1e3,
                         fail=nfail, fail_rate=nfail/len(gall)))
    s = pd.DataFrame(rows)

    # per (profile,n,mode): model fit over rtt>=1 and crossover tau*
    fit_rows = []
    for (prof, n, mode), g in s.groupby(["profile", "n", "mode"]):
        tsrv = g[g.rtt_ms == 0].tsrv_us.mean()
        gg = g[g.rtt_ms >= 1].sort_values("rtt_ms")
        # model L = t_net + t_srv ; t_net in us = 1000*rtt for ka (slope 1),
        # 2000*rtt for new small-token (slope 2); fit observed slope in ms/ms
        m, b, r2 = linfit(gg.rtt_ms.to_numpy(), gg.total_p50_us.to_numpy()/1e3)
        tau_star = (tsrv/1e3) / m if (m and not np.isnan(m) and m > 0) else np.nan  # ms
        fit_rows.append(dict(profile=prof, n=int(n), mode=mode, tsrv_us=tsrv,
                             slope_ms_per_ms=m, intercept_ms=b, r2=r2,
                             tau_star_ms=tau_star))
    f = pd.DataFrame(fit_rows)
    s.to_csv(os.path.join(OUTD, "en1_summary.csv"), index=False)
    f.to_csv(os.path.join(OUTD, "en1_fits.csv"), index=False)

    # console: n=20 headline table
    print("\n=== E-N1 latency vs RTT (n=20, medians; t_srv=server processing) ===")
    t20 = s[s.n == 20]
    for prof in t20.profile.unique():
        ka = t20[(t20.profile == prof) & (t20["mode"] == "ka")].set_index("rtt_ms")
        nw = t20[(t20.profile == prof) & (t20["mode"] == "new")].set_index("rtt_ms")
        if 0 not in ka.index:
            continue
        tsrv = ka.loc[0, "tsrv_us"]
        def rho_at(d, r):
            return d.loc[r, "rho"] if r in d.index else float("nan")
        print(f"  {prof:24s} t_srv={tsrv:8.1f}us  "
              f"rho_ka@20={rho_at(ka,20):.3f} @100={rho_at(ka,100):.3f}  "
              f"new L@20={nw.loc[20,'total_p50_us']/1e3 if 20 in nw.index else float('nan'):6.2f}ms")

    # relative overhead vs Ed at deployment RTTs (ka, n=20)
    print("\n  Relative end-to-end latency overhead vs Ed25519 (ka, n=20):")
    ov = []
    ed = t20[(t20.profile == "ed25519") & (t20["mode"] == "ka")].set_index("rtt_ms")
    for rtt in [1, 20, 50, 100, 200]:
        line = f"   RTT={rtt:>3}ms: "
        for prof in [p for p in REP if p in t20.profile.unique()]:
            d = t20[(t20.profile == prof) & (t20["mode"] == "ka")].set_index("rtt_ms")
            if rtt in d.index and rtt in ed.index:
                o = 100 * (d.loc[rtt, "total_p50_us"] / ed.loc[rtt, "total_p50_us"] - 1)
                line += f"{LABEL.get(prof,prof)}={o:6.2f}%  "
                ov.append(dict(rtt=rtt, profile=prof, overhead_pct=o))
        print(line)
    pd.DataFrame(ov).to_csv(os.path.join(OUTD, "en1_overhead_vs_ed.csv"), index=False)

    plot_en1(s, f)
    return s, f


def plot_en1(s, f):
    n = 20
    # Fig: latency vs RTT, ka vs new, representative profiles
    fig, axes = plt.subplots(1, 2, figsize=(9.5, 3.4), sharey=False)
    for ax, mode, title in [(axes[0], "ka", "Keep-alive (single RTT)"),
                            (axes[1], "new", "New connection")]:
        d = s[(s.n == n) & (s["mode"] == mode)]
        for prof in REP:
            g = d[d.profile == prof].sort_values("rtt_ms")
            if g.empty:
                continue
            ax.errorbar(g.rtt_ms, g.total_p50_us/1e3,
                        yerr=[(g.total_p50_us-g.p50_ci_lo_us)/1e3,
                              (g.p50_ci_hi_us-g.total_p50_us)/1e3],
                        marker=MARK.get(prof, "o"), ms=3.5, lw=1.1, capsize=2,
                        color=COL.get(prof), label=LABEL.get(prof, prof))
        ax.set_xscale("symlog", linthresh=1); ax.set_yscale("log")
        ax.set_xlabel("Round-trip time  τ  (ms)")
        ax.set_ylabel("Median transaction latency (ms)")
        ax.set_title(title)
    axes[0].legend(fontsize=6.5, ncol=2, frameon=False, loc="upper left")
    fig.tight_layout()
    fig.savefig(os.path.join(FIGD, "netfig1_latency_rtt.png"))
    plt.close(fig)

    # Fig: rho vs RTT (ka)
    fig, ax = plt.subplots(figsize=(5.2, 3.4))
    for prof in REP:
        g = s[(s.n == 20) & (s["mode"] == "ka") & (s.profile == prof)].sort_values("rtt_ms")
        if g.empty:
            continue
        ax.plot(g.rtt_ms, g.rho, marker=MARK.get(prof, "o"), ms=4, lw=1.3,
                color=COL.get(prof), label=LABEL.get(prof, prof))
    ax.axhline(0.5, color="gray", ls="--", lw=1)
    ax.set_xscale("symlog", linthresh=1)
    ax.set_xlabel("Round-trip time  τ  (ms)"); ax.set_ylabel(r"$\rho=t_{srv}/L$")
    ax.set_title("Server-cost share, keep-alive, n=20")
    ax.legend(fontsize=7, frameon=False)
    fig.tight_layout(); fig.savefig(os.path.join(FIGD, "netfig2_rho_rtt.png")); plt.close(fig)


# ---------------------------------------------------------------- E-N2
def analyze_en2(lat):
    en = lat[(lat.exp == "en2")].copy()
    if en.empty:
        print("[E-N2] no data"); return None
    rows = []
    for (prof, n, mode, loss), g in en.groupby(["profile", "n", "mode", "loss_pct"]):
        ok = g[g.status == 200]
        tot = ok.total_ns.to_numpy()
        p50, p95, p99 = pct(tot)
        rows.append(dict(profile=prof, n=int(n), mode=mode, loss_pct=loss,
                         samples=len(g), fail=int((g.status != 200).sum()),
                         fail_rate=(g.status != 200).mean(),
                         p50_us=p50/1e3, p95_us=p95/1e3, p99_us=p99/1e3,
                         tail_ratio=p99/p50 if p50 else np.nan))
    s = pd.DataFrame(rows)
    # amplification vs loss=0 baseline
    base = s[s.loss_pct == 0].set_index(["profile", "n", "mode"])[["p50_us", "p99_us"]]
    # NB: index with r["mode"], not r.mode — Series.mode is a built-in method
    # (众数), so the attribute returns the bound method instead of the column value.
    s["p50_amp"] = s.apply(lambda r: r.p50_us/base.loc[(r["profile"], r["n"], r["mode"]), "p50_us"], axis=1)
    s["p99_amp"] = s.apply(lambda r: r.p99_us/base.loc[(r["profile"], r["n"], r["mode"]), "p99_us"], axis=1)
    s.to_csv(os.path.join(OUTD, "en2_loss.csv"), index=False)
    print("\n=== E-N2 loss @RTT20 (n=20, new): P50/P99 amplification vs loss=0 ===")
    t = s[(s.n == 20) & (s["mode"] == "new")]
    for prof in t.profile.unique():
        g = t[t.profile == prof].sort_values("loss_pct")
        txt = "  ".join(f"p={int(r.loss_pct)}%:P50x{r.p50_amp:.2f}/P99x{r.p99_amp:.2f}/fail{r.fail_rate*100:.1f}%"
                        for r in g.itertuples())
        print(f"  {prof:24s} {txt}")

    fig, axes = plt.subplots(1, 2, figsize=(9.5, 3.3))
    for ax, mode, stat in [(axes[0], "new", "p50_us"), (axes[1], "new", "p99_us")]:
        for prof in REP:
            g = s[(s.n == 20) & (s["mode"] == mode) & (s.profile == prof)].sort_values("loss_pct")
            if g.empty:
                continue
            ax.plot(g.loss_pct, g[stat]/1e3, marker=MARK.get(prof, "o"), ms=4,
                    color=COL.get(prof), label=LABEL.get(prof, prof))
        ax.set_xlabel("Independent Bernoulli loss  p  (%)")
        ax.set_ylabel("Median (ms)" if stat == "p50_us" else "P99 (ms)")
        ax.set_title("New connection, n=20, RTT=20ms: " + ("median" if stat == "p50_us" else "P99 tail"))
    axes[0].legend(fontsize=6.5, frameon=False)
    fig.tight_layout(); fig.savefig(os.path.join(FIGD, "netfig3_loss.png")); plt.close(fig)
    return s


# ---------------------------------------------------------------- E-N3
def analyze_en3(tp):
    if tp is None or tp.empty:
        print("[E-N3] no data"); return None
    tp = tp[tp.completed > 0].copy()
    agg = tp.groupby(["profile", "n", "rtt_ms", "conc"]).agg(
        rps=("rps", "mean"), rps_sd=("rps", "std"),
        p50_us=("p50_ns", lambda x: np.median(x)/1e3),
        p99_us=("p99_ns", lambda x: np.median(x)/1e3),
        completed=("completed", "sum"), failed=("failed", "sum")).reset_index()
    agg.to_csv(os.path.join(OUTD, "en3_throughput.csv"), index=False)
    print("\n=== E-N3 throughput (n=20, rps over reps; Little: L=rps*W) ===")
    t = agg[agg.n == 20]
    for prof in t.profile.unique():
        g = t[t.profile == prof].sort_values(["rtt_ms", "conc"])
        txt = "  ".join(f"RTT{int(r.rtt_ms)}c{int(r.conc)}={r.rps:.0f}rps(P50{r.p50_us/1e3:.2f}ms)"
                        for r in g.itertuples())
        print(f"  {prof:24s} {txt}")

    fig, axes = plt.subplots(1, 3, figsize=(11, 3.2), sharey=True)
    for ax, rtt in zip(axes, sorted(t.rtt_ms.unique())):
        for prof in REP:
            g = t[(t.profile == prof) & (t.rtt_ms == rtt)].sort_values("conc")
            if g.empty:
                continue
            ax.errorbar(g.conc, g.rps, yerr=g.rps_sd, marker=MARK.get(prof, "o"),
                        ms=4, color=COL.get(prof), capsize=2, label=LABEL.get(prof, prof))
        ax.set_xlabel("Concurrent keep-alive clients  c")
        ax.set_title(f"RTT={int(rtt)}ms" if rtt else "RTT~0")
    axes[0].set_ylabel("Aggregate throughput (req/s)")
    axes[0].legend(fontsize=6, ncol=2, frameon=False)
    fig.tight_layout(); fig.savefig(os.path.join(FIGD, "netfig4_throughput.png")); plt.close(fig)
    return agg


# ---------------------------------------------------------------- E-N4
TAU_EN4_MS = 50.0
SDN_EST_B = 100  # small fixed response (status line + headers + 2-byte body)


def analyze_en4(lat, man):
    en = lat[(lat.exp == "en4") & (lat.status == 200)].copy()
    if en.empty:
        print("[E-N4] no data"); return None
    rows = []
    for (prof, n, rate), g in en.groupby(["profile", "n", "rate"]):
        tot = g.total_ns.to_numpy()
        p50, p95, p99 = pct(tot)
        tsrv_ms = np.median(g.verify_ns.to_numpy()) / 1e6
        b64 = man.get((prof, int(n)), (np.nan, np.nan))[1]
        Sup = len(REQ_PREFIX.format(p=prof)) + b64 + len(REQ_SUFFIX)  # same template as E-N5
        B = 1_000_000 if rate == "1mbit" else 46_000
        tser_ms = 8.0 * (Sup + SDN_EST_B) / B * 1000.0
        lpred = TAU_EN4_MS + tsrv_ms + tser_ms
        rows.append(dict(profile=prof, n=int(n), rate=rate, samples=len(g),
                         sup_b=Sup, tsrv_ms=tsrv_ms, tser_ms=tser_ms,
                         lpred_ms=lpred,
                         p50_ms=p50/1e6, p95_ms=p95/1e6, p99_ms=p99/1e6))
    s = pd.DataFrame(rows)
    s.to_csv(os.path.join(OUTD, "en4_bandwidth.csv"), index=False)
    print(f"\n=== E-N4 narrowband (RTT={TAU_EN4_MS:.0f}ms, ka): L=tau+t_srv+8S/B vs measured ===")
    for r in s.itertuples():
        print(f"  {r.profile:24s} n{r.n:<3} {r.rate:7s} S={r.sup_b:6.0f}B "
              f"pred={r.lpred_ms:7.1f}ms  measured P50={r.p50_ms:7.1f}ms "
              f"(ratio {r.p50_ms/r.lpred_ms:.2f})")
    # confirm the 1/B serialization slope by regressing measured P50 on wire bytes
    print("  slope check (measured P50 vs S_up+S_dn), theory 8/B:")
    for rate in ["1mbit", "46kbit"]:
        g = s[s.rate == rate]
        if len(g) >= 2:
            B = 1_000_000 if rate == "1mbit" else 46_000
            m, b, r2 = linfit((g.sup_b + SDN_EST_B).to_numpy(), g.p50_ms.to_numpy())
            mstar = 8.0 / B * 1000.0  # ms per byte
            print(f"    {rate:7s}: fitted {m:.5f} ms/byte vs theory {mstar:.5f} "
                  f"(ratio {m/mstar:.2f}), intercept {b:.1f}ms, R2={r2:.3f}")

    fig, ax = plt.subplots(figsize=(5.4, 3.6))
    for rate, mk in [("1mbit", "o"), ("46kbit", "^")]:
        g = s[s.rate == rate]
        if g.empty:
            continue
        ax.scatter(g.lpred_ms, g.p50_ms, marker=mk, s=36, label=rate)
    lim = max(s.lpred_ms.max(), s.p50_ms.max()) * 1.1
    ax.plot([0, lim], [0, lim], color="gray", ls="--", lw=1, label="y = x (model)")
    ax.set_xlabel(f"Predicted latency  τ+t_srv+8S/B  (ms), τ={TAU_EN4_MS:.0f}ms")
    ax.set_ylabel("Measured median transaction latency (ms)")
    ax.legend(fontsize=7, frameon=False)
    fig.tight_layout(); fig.savefig(os.path.join(FIGD, "netfig5_bandwidth.png")); plt.close(fig)
    return s


# ---------------------------------------------------------------- E-N5
REQ_PREFIX = "GET /authz/{p} HTTP/1.1\r\nHost: netbed\r\nAuthorization: Bearer "
REQ_SUFFIX = "\r\nX-Seq: 1\r\nConnection: close\r\n\r\n"


def analyze_en5(seg, man):
    if seg is None or seg.empty:
        print("[E-N5] no data"); return None
    # The wire model predicts NET-payload segments; a full-speed burst also
    # triggers a small number of TCP retransmissions, so allow up to RET_TOL.
    RET_TOL = 0.05
    rows = []
    for r in seg.itertuples():
        b64 = man.get((r.profile, int(r.n)), (np.nan, np.nan))[1]
        if np.isnan(b64):
            pred = np.nan; rel = np.nan
        else:
            Sup = len(REQ_PREFIX.format(p=r.profile)) + b64 + len(REQ_SUFFIX)
            pred = math.ceil(Sup / MSS)
            rel = max(0, int(r.meas_up) - pred) / pred
        extra = max(0, int(r.meas_up) - pred)
        exact = (pred == int(r.meas_up))
        match = ((not np.isnan(rel)) and (int(r.meas_up) >= pred)
                 and ((extra <= 1) or (rel <= RET_TOL)) and (int(r.meas_dn) == 1))
        rows.append(dict(profile=r.profile, n=int(r.n), b64_b=b64,
                         pred_up=pred, meas_up=int(r.meas_up), dn=int(r.meas_dn),
                         retrans_pct=round(100*rel, 2) if not np.isnan(rel) else np.nan,
                         exact=exact, match=match))
    s = pd.DataFrame(rows)
    s.to_csv(os.path.join(OUTD, "en5_segments.csv"), index=False)
    print(f"\n=== E-N5 segmentation: net model ceil(S_up/{MSS}) vs tcpdump (incl. burst retrans) ===")
    print(f"  exact N_up & N_dn=1: {int(s.exact.sum())}/{len(s)}; "
          f"within {int(RET_TOL*100)}% (or +1 seg): {int(s.match.sum())}/{len(s)} "
          f"({s.match.mean()*100:.1f}%)")
    bad = s[~s.match]
    if len(bad):
        print("  outside tolerance:")
        for r in bad.itertuples():
            print(f"    {r.profile} n{r.n}: pred {r.pred_up} vs meas {r.meas_up} "
                  f"(retrans {r.retrans_pct}%, dn {r.dn})")
    return s


# ---------------------------------------------------------------- E-N6
def analyze_en6(fp):
    if fp is None or fp.empty:
        print("[E-N6] no data"); return None
    fp.to_csv(os.path.join(OUTD, "en6_footprint.csv"), index=False)
    print("\n=== E-N6 footprint ===")
    for r in fp.itertuples():
        print(f"  {r.backend:12s} binary={int(r.binary_b)/1e6:.2f}MB "
              f"stripped={int(r.stripped_b)/1e6:.2f}MB peakRSS={int(r.rss_kb)/1024:.1f}MB")
    return fp


# ---------------------------------------------------------------- cross-check
def crosscheck_micro(lat):
    """network t_srv (full server handling) vs e6 whole-chain and e56 pure verify."""
    en1 = lat[(lat.exp == "en1") & (lat.status == 200) & (lat.rtt_ms == 0)]
    if en1.empty:
        return
    net = en1[en1.n == 20].groupby("profile").verify_ns.median()
    e6 = load("e6_profiles_verify.csv")
    e56 = load("e56_latency_avx2.csv")
    print("\n=== cross-check fn/ed ratio at n=20 (tau=0) ===")
    if "fndsa512" in net.index and "ed25519" in net.index:
        print(f"  network t_srv fn/ed = {net['fndsa512']/net['ed25519']:.3f}")
    if e6 is not None:
        e6 = e6[e6.n == 20]
        m = e6.groupby("profile").ns.median()
        for a, b in [("all-fndsa512", "all-ed"), ("mixed-mldsa87-root-fn", "all-ed")]:
            if a in m.index and b in m.index:
                print(f"  e6 whole-chain {a.split('-')[0] if 'mixed' not in a else 'mixed'}/ed = {m[a]/m[b]:.3f}")
    if e56 is not None:
        v = e56[(e56.op == "verify_chain") & (e56.n == 20)].groupby("alg").ns.median()
        # alg names observed: Ed25519, FN-DSA-512, ...
        for a in ["FN-DSA-512", "Falcon-512", "FN_DSA_512"]:
            if a in v.index and "Ed25519" in v.index:
                print(f"  e56 pure-verify {a}/Ed = {v[a]/v['Ed25519']:.3f}")
                break


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.parse_args()
    lat = load("net_latency.csv")
    tp = load("net_throughput.csv")
    seg = load("net_segments_meas.csv")
    fp = load("net_footprint.csv")
    man = manifest_map()
    print(f"manifest entries: {len(man)}; latency rows: {0 if lat is None else len(lat)}; "
          f"throughput rows: {0 if tp is None else len(tp)}")
    if lat is not None:
        analyze_en1(lat, man)
        analyze_en2(lat)
        analyze_en4(lat, man)
        crosscheck_micro(lat)
    analyze_en3(tp)
    analyze_en5(seg, man)
    analyze_en6(fp)
    print(f"\nfigures -> {FIGD}\nsummaries -> {OUTD}")


if __name__ == "__main__":
    main()
