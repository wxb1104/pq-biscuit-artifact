import pandas as pd, numpy as np, os
D=os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','data')
OUT=os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','analysis')
B=10000
def boot(vals,q=0.5,seed=0,B=B):
    vals=np.asarray(vals,float); n=len(vals)
    rng=np.random.default_rng(seed)
    idx=rng.integers(0,n,(B,n))
    s=np.quantile(vals[idx],q,axis=1)
    return np.quantile(vals,q),np.percentile(s,2.5),np.percentile(s,97.5)
def rel(p,lo,hi): return 100*max(p-lo,hi-p)/abs(p) if p else np.nan

nl=pd.read_csv(os.path.join(D,'net_latency.csv'))
# pure server chain verify: zero-latency baseline (rtt0, loss0, ka), n20
sub=nl[(nl.exp=='en1')&(nl.n==20)&(nl.loss_pct==0)&(nl.rtt_ms==0)&(nl['mode']=='ka')]
rows=[]
for prof,g in sub.groupby('profile'):
    p,lo,hi=boot(g.verify_ns.values,seed=abs(hash('v20r0'+prof))%(2**31))
    rows.append(dict(profile=prof,verify_us=p/1000,lo=lo/1000,hi=hi/1000,rel=rel(p,lo,hi),reps=len(g)))
v20=pd.DataFrame(rows).sort_values('verify_us'); v20.to_csv(os.path.join(OUT,'ci_n20_verify.csv'),index=False)
print('n20 pure server chain verify (us), rtt0 baseline:')
for _,x in v20.iterrows():
    print(f"  {x.profile:>20} {x.verify_us:8.1f} [{x.lo:8.1f},{x.hi:8.1f}] +-{x.rel:4.1f}% n={x.reps}")
