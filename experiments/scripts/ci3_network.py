import pandas as pd, numpy as np, os
D=os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','data')
OUT=os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','analysis')
B=10000
REPS=['ed25519','mldsa87','fndsa512','slhdsa128f','hyb-ed-fndsa512','mix-mldsa87-fndsa512']

def boot(vals,q=0.5,seed=0,B=B):
    vals=np.asarray(vals,float); n=len(vals)
    rng=np.random.default_rng(seed)
    idx=rng.integers(0,n,(B,n))
    s=np.quantile(vals[idx],q,axis=1)
    return np.quantile(vals,q),np.percentile(s,2.5),np.percentile(s,97.5)

def rel(p,lo,hi): return 100*max(p-lo,hi-p)/abs(p) if p else np.nan

nl=pd.read_csv(os.path.join(D,'net_latency.csv'))

# 1. n20 chain server-verify (t_srv), all 15 profiles; rtt20 loss0 ka
rows=[]
sub=nl[(nl.exp=='en1')&(nl.n==20)&(nl.loss_pct==0)&(nl.rtt_ms==20)&(nl['mode']=='ka')]
for prof,g in sub.groupby('profile'):
    p,lo,hi=boot(g.verify_ns.values,seed=abs(hash('v20'+prof))%(2**31))
    rows.append(dict(profile=prof,verify_us=p/1000,lo=lo/1000,hi=hi/1000,rel=rel(p,lo,hi),reps=len(g)))
v20=pd.DataFrame(rows); v20.to_csv(os.path.join(OUT,'ci_n20_verify.csv'),index=False)
print('n20 server chain verify (us):')
for _,x in v20.iterrows():
    print(f"  {x.profile:>20} {x.verify_us:8.1f} [{x.lo:8.1f},{x.hi:8.1f}] +-{x.rel:4.1f}%")

# 2. E-N1 RTT total median (ka) for representative profiles, rtt 20/50/200
rows=[]
s1=nl[(nl.exp=='en1')&(nl.n==20)&(nl.loss_pct==0)&(nl['mode']=='ka')&(nl.profile.isin(REPS))]
for (prof,rtt),g in s1.groupby(['profile','rtt_ms']):
    p,lo,hi=boot(g.total_ns.values,seed=abs(hash('rtt'+prof+str(rtt)))%(2**31))
    rows.append(dict(profile=prof,rtt=rtt,total_ms=p/1e6,lo=lo/1e6,hi=hi/1e6,rel=rel(p,lo,hi)))
rtt_df=pd.DataFrame(rows); rtt_df.to_csv(os.path.join(OUT,'ci_rtt.csv'),index=False)
print('\nRTT total median (ms), ka n20:')
for _,x in rtt_df.iterrows():
    print(f"  RTT{x.rtt:<4} {x.profile:>20} {x.total_ms:8.1f} [{x.lo:8.1f},{x.hi:8.1f}] +-{x.rel:4.1f}%")

# 3. E-N2 loss p50/p99 (new, rtt20, n20)
rows=[]
s2=nl[(nl.exp=='en2')&(nl.n==20)&(nl.rtt_ms==20)&(nl['mode']=='new')&(nl.profile.isin(REPS))]
for (prof,loss),g in s2.groupby(['profile','loss_pct']):
    for q,lab in [(0.5,'p50'),(0.99,'p99')]:
        p,lo,hi=boot(g.total_ns.values,q=q,seed=abs(hash('loss'+prof+str(loss)+lab))%(2**31))
        rows.append(dict(profile=prof,loss=loss,q=lab,ms=p/1e6,lo=lo/1e6,hi=hi/1e6))
loss_df=pd.DataFrame(rows); loss_df.to_csv(os.path.join(OUT,'ci_loss.csv'),index=False)
print('\nLoss p50/p99 (ms), new n20 rtt20:')
for (prf,ls),gg in loss_df.groupby(['profile','loss']):
    a=gg[gg.q=='p50'].iloc[0]; b=gg[gg.q=='p99'].iloc[0]
    print(f"  loss{ls} {prf:>20} p50={a.ms:7.1f}[{a.lo:7.1f},{a.hi:7.1f}] p99={b.ms:8.1f}[{b.lo:8.1f},{b.hi:8.1f}]")

# 4. E-N4 constrained completion n20
rows=[]
s4=nl[(nl.exp=='en4')&(nl.n==20)&(nl.profile.isin(REPS))]
for (prof,rate),g in s4.groupby(['profile','rate']):
    p,lo,hi=boot(g.total_ns.values,seed=abs(hash('en4'+prof+rate))%(2**31))
    rows.append(dict(profile=prof,rate=rate,ms=p/1e6,lo=lo/1e6,hi=hi/1e6,rel=rel(p,lo,hi)))
en4=pd.DataFrame(rows); en4.to_csv(os.path.join(OUT,'ci_en4.csv'),index=False)
print('\nConstrained completion (ms) n20:')
for _,x in en4.iterrows():
    print(f"  {x.rate:<7} {x.profile:>20} {x.ms:9.1f} [{x.lo:9.1f},{x.hi:9.1f}] +-{x.rel:4.1f}%")

# 5. E-N3 throughput (3 reps)
tp=pd.read_csv(os.path.join(D,'net_throughput.csv'))
rows=[]
for (prof,n,rtt,conc),g in tp.groupby(['profile','n','rtt_ms','conc']):
    if prof not in REPS or n!=20 or rtt!=20: continue
    p,lo,hi=boot(g.rps.values,seed=abs(hash('tp'+prof+str(conc)))%(2**31))
    rows.append(dict(profile=prof,conc=conc,rps=p,lo=lo,hi=hi))
tpdf=pd.DataFrame(rows); tpdf.to_csv(os.path.join(OUT,'ci_throughput.csv'),index=False)
print('\nThroughput rps n20 rtt20 (3 reps):')
for _,x in tpdf.iterrows():
    print(f"  c{x.conc:<3} {x.profile:>20} {x.rps:7.1f} [{x.lo:7.1f},{x.hi:7.1f}]")
