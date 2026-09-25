import pandas as pd, numpy as np, os
D=os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','data')
OUT=os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','analysis')
B=10000

def boot_ratio(num, den, seed, B=B):
    num=np.asarray(num,float); den=np.asarray(den,float)
    rng=np.random.default_rng(seed)
    ii=rng.integers(0,len(num),(B,len(num)))
    jj=rng.integers(0,len(den),(B,len(den)))
    r=np.median(num[ii],1)/np.median(den[jj],1)
    point=np.median(num)/np.median(den)
    return point,np.percentile(r,2.5),np.percentile(r,97.5)

# ---- pregen: online realtime vs offline (only sign remains online) ----
pr=pd.read_csv(os.path.join(D,'e6_pregen.csv'))
rows=[]
for alg,g in pr.groupby('alg'):
    sign=g[g.phase=='append_sign'].ns.values
    real=g[g.phase=='append_realtime'].ns.values
    seed=abs(hash('pregen'+alg))%(2**31)
    r,lo,hi=boot_ratio(sign,real,seed)   # fraction of online time still needed
    rows.append(dict(alg=alg, online_remaining=r, saving=1-r,
                     saving_lo=1-hi, saving_hi=1-lo,
                     real_us=np.median(real)/1000, sign_us=np.median(sign)/1000))
preg=pd.DataFrame(rows); preg.to_csv(os.path.join(OUT,'ci_pregen_saving.csv'),index=False)
print('PREGEN saving %:')
for _,x in preg.iterrows():
    print(f"  {x.alg:>17} saving={100*x.saving:6.2f}% [{100*x.saving_lo:6.2f},{100*x.saving_hi:6.2f}]")

# ---- hybrid verify_chain overhead vs Ed (e56, both builds, n=10) ----
rows=[]
for build in ['avx2','portable']:
    df=pd.read_csv(os.path.join(D,f'e56_latency_{build}.csv'))
    ed=df[(df.op=='verify_chain')&(df.alg=='Ed25519')]
    for n in [5,10]:
        edv=ed[ed.n==n].ns.values
        for halg in ['HybridEdMldsa44','HybridEdFndsa512']:
            hv=df[(df.op=='verify_chain')&(df.alg==halg)&(df.n==n)].ns.values
            if len(hv)==0: continue
            seed=abs(hash('hyb'+build+halg+str(n)))%(2**31)
            r,lo,hi=boot_ratio(hv,edv,seed)
            rows.append(dict(build=build,n=n,hybrid=halg,ratio=r,lo=lo,hi=hi))
hyb=pd.DataFrame(rows); hyb.to_csv(os.path.join(OUT,'ci_hybrid_overhead.csv'),index=False)
print('\nHYBRID verify_chain ratio vs Ed:')
for _,x in hyb.iterrows():
    print(f"  {x.build:<8} n{x.n:<2} {x.hybrid:>17} ratio={x.ratio:.3f} [{x.lo:.3f},{x.hi:.3f}]")
