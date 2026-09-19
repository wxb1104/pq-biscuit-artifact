#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""E6 analysis: fidelity matrix (fig17), pregen amortisation (fig18),
deployment profiles (fig19). Prints numeric summaries for sanity checks."""
import os, json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
FIG = os.path.join(HERE, "figures")
os.makedirs(FIG, exist_ok=True)

ALG_ORDER = ["Ed25519","Mldsa44","Mldsa65","Mldsa87","Fndsa512","Fndsa1024",
             "HybridEdMldsa44","HybridEdFndsa512",
             "Slhdsa128s","Slhdsa128f","Slhdsa256s","Slhdsa256f"]
SHORT = {"Ed25519":"Ed25519","Mldsa44":"ML-DSA-44","Mldsa65":"ML-DSA-65","Mldsa87":"ML-DSA-87",
         "Fndsa512":"FN-DSA-512","Fndsa1024":"FN-DSA-1024",
         "HybridEdMldsa44":"Hyb(Ed,ML44)","HybridEdFndsa512":"Hyb(Ed,FN512)",
         "Slhdsa128s":"SLH-128s","Slhdsa128f":"SLH-128f",
         "Slhdsa256s":"SLH-256s","Slhdsa256f":"SLH-256f"}
CHECKS = [("f1_seal_atten_verify","seal+atten\n+verify"),
          ("f2_datalog_write_denied","Datalog\nwrite denied"),
          ("f3_unsealed_roundtrip","unsealed\nroundtrip"),
          ("f4_key_bytes_roundtrip","key byte\nroundtrip"),
          ("f5_wrong_root_rejected","wrong root\nrejected"),
          ("f6_tamper_rejected","tamper\nrejected"),
          ("f7_third_party_pq","3rd-party\nPQ block"),
          ("f8_third_party_wrong_key","3rd-party\nwrong key"),
          ("f9_hybrid_cross_combo","hybrid cross-\ncombo reject")]

plt.rcParams.update({"font.size":9,"axes.edgecolor":"#333333","axes.linewidth":0.8,
                     "figure.dpi":200,"savefig.dpi":200})

# ---------------- fig17 fidelity matrix ----------------
fid = pd.read_csv(os.path.join(DATA,"e6_fidelity.csv"))
mat = pd.DataFrame(index=ALG_ORDER, columns=[c[0] for c in CHECKS])
for _,r in fid.iterrows():
    mat.loc[r["alg"], r["check"]] = 1 if r["result"]=="PASS" else 0
M = mat.to_numpy(dtype=float)  # NaN where absent (f9 non-hybrid)
fig,ax = plt.subplots(figsize=(8.6,6.3))
for i,alg in enumerate(ALG_ORDER):
    for j,(ck,_) in enumerate(CHECKS):
        v = M[i,j]
        if np.isnan(v):
            c="white"; txt="–"; tc="#999999"
        elif v==1:
            c="#2e8b57"; txt="✓"; tc="white"
        else:
            c="#c0392b"; txt="✕"; tc="white"
        ax.add_patch(plt.Rectangle((j,i),1,1,facecolor=c,edgecolor="white",lw=1.2))
        ax.text(j+0.5,i+0.5,txt,ha="center",va="center",color=tc,fontsize=11,fontweight="bold")
ax.set_xlim(0,len(CHECKS)); ax.set_ylim(len(ALG_ORDER),0)
ax.set_xticks(np.arange(len(CHECKS))+0.5); ax.set_xticklabels([c[1] for c in CHECKS],fontsize=7.6)
ax.set_yticks(np.arange(len(ALG_ORDER))+0.5); ax.set_yticklabels([SHORT[a] for a in ALG_ORDER])
ax.tick_params(length=0); ax.xaxis.tick_top()
for s in ax.spines.values(): s.set_visible(False)
ax.set_title("Functional fidelity & security-binding matrix (all checks PASS)",fontsize=10.5,pad=36)
legend = [Patch(facecolor="#2e8b57",label="PASS"),Patch(facecolor="white",label="N/A (f9 hybrid-only)")]
ax.legend(handles=legend,loc="lower center",bbox_to_anchor=(0.5,-0.11),ncol=2,frameon=False,fontsize=8)
# fixed margins: room for the two-line top column headers + title above, legend below
plt.subplots_adjust(left=0.16,right=0.99,top=0.77,bottom=0.15)
plt.savefig(os.path.join(FIG,"fig17_fidelity_matrix.png"),dpi=200)
plt.close()
npass = int(np.nansum(M==1)); nfail=int(np.nansum(M==0)); nna=int(np.isnan(M).sum())
print(f"fig17: PASS={npass} FAIL={nfail} N/A={nna}")

# ---------------- fig18 pregen amortisation ----------------
pg = pd.read_csv(os.path.join(DATA,"e6_pregen.csv"))
g = pg.groupby(["alg","phase"])["ns"].agg(med="median",q1=lambda x:np.percentile(x,25),
                                         q3=lambda x:np.percentile(x,75)).reset_index()
piv = g.pivot(index="alg",columns="phase",values="med").reindex(ALG_ORDER)
piv_us = piv/1000.0
phases = ["keygen","append_sign","append_realtime"]
labels = {"keygen":"key generation (offline)","append_sign":"online append, pre-minted key (sign only)",
          "append_realtime":"naive online append (keygen+sign)"}
colors = {"keygen":"#7f8c8d","append_sign":"#2e8b57","append_realtime":"#c0392b"}
x = np.arange(len(ALG_ORDER)); w=0.27
fig,ax=plt.subplots(figsize=(11.4,4.9))
for k,ph in enumerate(phases):
    vals=piv_us[ph].to_numpy(dtype=float)
    ax.bar(x+(k-1)*w, vals, w, label=labels[ph], color=colors[ph], edgecolor="white",lw=.4)
ax.set_yscale("log"); ax.set_ylabel("time per attenuation hop (µs, log scale)")
ax.set_xticks(x); ax.set_xticklabels([SHORT[a] for a in ALG_ORDER],rotation=40,ha="right")
ax.grid(axis="y",ls=":",alpha=.5)
ax.legend(frameon=False,fontsize=8,loc="upper left")
ax.set_title("Fresh-key cost: offline pre-generation removes keygen from the online path",fontsize=10.5)
# annotate online saving only where it is substantial (Falcon family is keygen-bound)
for alg in ("Fndsa512","Fndsa1024","HybridEdFndsa512"):
    xi=ALG_ORDER.index(alg); so=piv_us.loc[alg,"append_sign"]; saving=100*(1-so/piv_us.loc[alg,"append_realtime"])
    ax.annotate(f"−{saving:.0f}% online",(xi+w, max(so,0.05)),
                textcoords="offset points",xytext=(0,5),ha="center",fontsize=7.6,color="#1b5e3b",fontweight="bold")
ax.text(0.5,0.972,"SLH-DSA is signing-dominated: pre-generation removes only keygen (online saving ≤13%)",
        transform=ax.transAxes,fontsize=8,color="#444444",va="top",ha="center",
        bbox=dict(boxstyle="round,pad=0.35",fc="white",ec="#bbbbbb",lw=0.7,alpha=0.95))
_lo,_hi = ax.get_ylim(); ax.set_ylim(_lo, _hi*1.35)
plt.tight_layout(); plt.savefig(os.path.join(FIG,"fig18_pregen.png"),bbox_inches="tight"); plt.close()
print("\nfig18 per-algorithm (µs medians): keygen | sign-only | realtime | online saving% | additivity(kg+sign)/rt")
for alg in ALG_ORDER:
    kg=piv_us.loc[alg,"keygen"]; so=piv_us.loc[alg,"append_sign"]; rt=piv_us.loc[alg,"append_realtime"]
    sv=100*(1-so/rt); ad=(kg+so)/rt
    print(f"  {SHORT[alg]:>14}: kg={kg:9.1f} sign={so:9.1f} rt={rt:9.1f}  saving={sv:5.1f}%  add={ad:4.2f}")

# ---------------- fig19 deployment profiles ----------------
sz = pd.read_csv(os.path.join(DATA,"e6_profiles_size.csv"))
vf = pd.read_csv(os.path.join(DATA,"e6_profiles_verify.csv"))
vm = vf.groupby(["profile","n"])["ns"].median().reset_index()
vm["us"]=vm["ns"]/1000.0
profiles=["all-ed","all-mldsa44","all-fndsa512","hybrid-ed-mldsa44","hybrid-ed-fndsa512",
          "mixed-mldsa87-root-fn","mixed-slh128s-root-fn"]
plab={"all-ed":"all Ed25519 (classical)","all-mldsa44":"all ML-DSA-44","all-fndsa512":"all FN-DSA-512",
      "hybrid-ed-mldsa44":"all Hyb(Ed,ML44)","hybrid-ed-fndsa512":"all Hyb(Ed,FN512)",
      "mixed-mldsa87-root-fn":"ML-87 root + FN-512 hops","mixed-slh128s-root-fn":"SLH-128s root + FN-512 hops"}
pcol={"all-ed":"#7f8c8d","all-mldsa44":"#2471a3","all-fndsa512":"#1e8449",
      "hybrid-ed-mldsa44":"#b9770e","hybrid-ed-fndsa512":"#af601a",
      "mixed-mldsa87-root-fn":"#c0392b","mixed-slh128s-root-fn":"#16a085"}
ns=sorted(sz["n"].unique())
fig,(ax1,ax2)=plt.subplots(1,2,figsize=(11.5,4.6))
for p in profiles:
    s=sz[sz.profile==p].set_index("n").reindex(ns)["size_bytes"]/1024.0
    v=vm[vm.profile==p].set_index("n").reindex(ns)["us"]
    ax1.plot(ns,s,marker="o",ms=3.5,lw=1.6,color=pcol[p],label=plab[p])
    ax2.plot(ns,v,marker="s",ms=3.5,lw=1.6,color=pcol[p],label=plab[p])
ax1.axhline(4,ls="--",color="#555",lw=1); ax1.text(0.1,4.15,"4 KiB budget",fontsize=7.5,color="#555")
ax1.axhline(8,ls=":",color="#999",lw=1); ax1.text(0.1,8.15,"8 KiB",fontsize=7.5,color="#999")
ax1.set_xlabel("attenuation depth n"); ax1.set_ylabel("sealed token size (KiB)")
ax1.set_yscale("log"); ax1.grid(ls=":",alpha=.5)
ax2.set_xlabel("attenuation depth n"); ax2.set_ylabel("full-chain verification (µs)")
ax2.grid(ls=":",alpha=.5)
ax2.legend(fontsize=7.4,frameon=False,loc="upper left")
ax1.set_title("(a) sealed token size vs depth",fontsize=10)
ax2.set_title("(b) verification latency vs depth (AVX2)",fontsize=10)
ax1.margins(y=0.10); ax2.margins(y=0.12)
plt.tight_layout(); plt.savefig(os.path.join(FIG,"fig19_profiles.png"),bbox_inches="tight"); plt.close()
print("\nfig19 profiles at n=20:")
for p in profiles:
    s20=sz[(sz.profile==p)&(sz.n==20)]["size_bytes"].iloc[0]/1024.0
    v20=vm[(vm.profile==p)&(vm.n==20)]["us"].iloc[0]
    s0=sz[(sz.profile==p)&(sz.n==0)]["size_bytes"].iloc[0]
    print(f"  {plab[p]:>30}: n0={s0:6d} B  n20={s20:7.1f} KiB  verify(n20)={v20:8.1f} µs")

# dump summary json
summary={"fidelity":{"pass":npass,"fail":nfail,"na":nna},
         "pregen":{SHORT[a]:{"keygen_us":float(piv_us.loc[a,"keygen"]),
                             "sign_only_us":float(piv_us.loc[a,"append_sign"]),
                             "realtime_us":float(piv_us.loc[a,"append_realtime"]),
                             "online_saving_pct":float(100*(1-piv_us.loc[a,"append_sign"]/piv_us.loc[a,"append_realtime"]))}
                   for a in ALG_ORDER},
         "profiles_n20":{plab[p]:{"size_KiB":float(sz[(sz.profile==p)&(sz.n==20)]["size_bytes"].iloc[0]/1024),
                                  "verify_us":float(vm[(vm.profile==p)&(vm.n==20)]["us"].iloc[0])} for p in profiles}}
with open(os.path.join(DATA,"e6_summary.json"),"w") as f:
    json.dump(summary,f,indent=2)
print("\nwrote fig17/18/19 and e6_summary.json")
