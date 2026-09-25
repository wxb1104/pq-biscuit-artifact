import pandas as pd, numpy as np, os
D=os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','data')
OUT=os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','analysis')
os.makedirs(OUT, exist_ok=True)
B=10000

def boot(vals, stat=np.median, seed=0, B=B):
    vals=np.asarray(vals,float); n=len(vals)
    rng=np.random.default_rng(seed)
    idx=rng.integers(0,n,size=(B,n))
    s=stat(vals[idx],axis=1)
    return stat(vals), np.percentile(s,2.5), np.percentile(s,97.5)

def rel(p,lo,hi):
    return 100*max(p-lo,hi-p)/abs(p) if p!=0 else np.nan

# ---------- 1. e56 micro timing (both builds), all groups ----------
rows=[]
for build in ['avx2','portable']:
    df=pd.read_csv(os.path.join(D,f'e56_latency_{build}.csv'))
    for (alg,op,n),g in df.groupby(['alg','op','n']):
        seed=abs(hash((build,alg,op,n)))%(2**31)
        p,lo,hi=boot(g.ns.values,seed=seed)
        rows.append(dict(build=build,alg=alg,op=op,n=n,median_ns=p,lo=lo,hi=hi,rel_halfwidth_pct=rel(p,lo,hi),reps=len(g)))
pd.DataFrame(rows).to_csv(os.path.join(OUT,'ci_e56.csv'),index=False)
print('ci_e56 rows',len(rows))

# ---------- 2. pregen online saving ----------
pr=pd.read_csv(os.path.join(D,'e6_pregen.csv'))
print('pregen phases:',sorted(pr.phase.unique()))
# identify online vs offline(pregen) phase names
phases=sorted(pr.phase.unique())
rows=[]
for alg,g in pr.groupby('alg'):
    by={ph:g[g.phase==ph].ns.values for ph in phases}
    # saving relative to the fully-online append phase; use median per phase then ratios via bootstrap
    meds={ph:np.median(v) for ph,v in by.items() if len(v)}
    rows.append(dict(alg=alg, **{f'med_{ph}':meds.get(ph,np.nan) for ph in phases}))
pd.DataFrame(rows).to_csv(os.path.join(OUT,'ci_pregen_medians.csv'),index=False)
print('pregen algs',len(rows))
