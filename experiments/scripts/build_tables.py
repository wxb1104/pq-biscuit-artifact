#!/usr/bin/env python3
# Build the three summary tables that replace the per-scheme line charts.
# Portable layout: run from experiments/scripts, data is one level up.
import pandas as pd, numpy as np, os
B=os.path.abspath(os.path.join(os.path.dirname(__file__),'..'))
OUT=B+'/table_fragments'
os.makedirs(OUT,exist_ok=True)

e56=pd.read_csv(B+'/analysis/ci_e56.csv')
preg=pd.read_csv(B+'/analysis/ci_pregen_saving.csv')
n20=pd.read_csv(B+'/analysis/ci_n20_verify.csv')
en1=pd.read_csv(B+'/netbed/analysis/en1_summary.csv')
loss=pd.read_csv(B+'/analysis/ci_loss.csv')
en4=pd.read_csv(B+'/analysis/ci_en4.csv')
fp=pd.read_csv(B+'/netbed/analysis/en6_footprint.csv')
psize=pd.read_csv(B+'/data/e6_profiles_size.csv')
pver=pd.read_csv(B+'/data/e6_profiles_verify.csv')

def persig(build,alg):
    d=e56[(e56.build==build)&(e56.alg==alg)&(e56.op=='verify_chain')]
    v0=d[d.n==0].median_ns.values[0]
    for nn in (10,5,2,1):
        r=d[d.n==nn]
        if len(r): return (r.median_ns.values[0]-v0)/nn/1000.0
    return np.nan

rows=[('Ed25519','Ed25519',126),
 ('ML-DSA-44','Mldsa44',3768),('ML-DSA-65','Mldsa65',5297),('ML-DSA-87','Mldsa87',7255),
 ('FN-DSA-512','Fndsa512',1588),('FN-DSA-1024','Fndsa1024',3101),
 ('SLH-DSA-128s','Slhdsa128s',7922),('SLH-DSA-128f','Slhdsa128f',17156),
 ('SLH-DSA-256s','Slhdsa256s',29892),('SLH-DSA-256f','Slhdsa256f',49956),
 ('Hyb(Ed,ML-44)','HybridEdMldsa44',3864),('Hyb(Ed,FN-512)','HybridEdFndsa512',1684)]
pmap=dict(zip(preg.alg,preg.saving*100))
L=[r'\begin{table}[t]',r'\centering\small',
 r'\caption{Cryptographic microbenchmark. Per-hop sealed size $b$, per-signature verification on AVX2 and portable builds, and the online cost removed by offline key pre-generation ($\eta$, Eq.~(18)).}',
 r'\label{tab:micro}',r'\begin{tabular}{lrrrr}',r'\hline',
 r'Scheme & $b$ (B) & verify AVX2 ($\mu$s) & verify portable ($\mu$s) & $\eta$ (\%)\\',r'\hline']
for disp,alg,b in rows:
    L.append(f'{disp} & {b} & {persig("avx2",alg):.1f} & {persig("portable",alg):.1f} & {pmap.get(alg,np.nan):.1f} \\\\')
L += [r'\hline',r'\end{tabular}',r'\end{table}']
open(OUT+'/table_micro.tex','w').write('\n'.join(L))

def rho(prof,rtt):
    d=en1[(en1['profile']==prof)&(en1.n==20)&(en1['mode']=='ka')&(en1.rtt_ms==rtt)]
    return d.rho.values[0] if len(d) else np.nan
rss=dict(zip(fp.backend,fp.rss_kb/1024.0))
nrows=[('Ed','ed25519','ed25519'),('Mixed (ours)','mix-mldsa87-fndsa512','fndsa512'),
 ('FN-DSA-512','fndsa512','fndsa512'),('ML-DSA-87','mldsa87','fndsa512'),
 ('SLH-DSA-128f','slhdsa128f','slhdsa128f')]
N=[r'\begin{table}[t]',r'\centering\small',
 r'\caption{Network effects at key operating points (depth twenty): server processing $t_{\rm srv}$ at zero emulated delay, the server share $\rho$ (Eq.~(21)) at $20$ and $100$\,ms paths, the $99$th-percentile latency at $5\%$ loss, completion over a $46$\,kbps link, and peak resident memory.}',
 r'\label{tab:neteffects}',r'\begin{tabular}{lrrrrrr}',r'\hline',
 r'Profile & $t_{\rm srv}$ (ms) & $\rho_{20}$ & $\rho_{100}$ & p99 loss (s) & 46\,kbps (s) & RSS (MiB)\\',r'\hline']
for disp,p,fpk in nrows:
    d1=n20[n20.profile==p].verify_us.values[0]/1000
    dl=loss[(loss.profile==p)&(loss.loss==5)&(loss.q=='p99')].ms.values[0]/1000
    nb=en4[(en4.profile==p)&(en4.rate=='46kbit')].ms.values[0]/1000
    N.append(f'{disp} & {d1:.2f} & {rho(p,20):.2f} & {rho(p,100):.2f} & {dl:.2f} & {nb:.1f} & {rss.get(fpk,np.nan):.1f} \\\\')
N += [r'\hline',r'\end{tabular}',r'\end{table}']
open(OUT+'/table_net.tex','w').write('\n'.join(N))

prof_order=[('Ed','all-ed'),('ML-DSA-44','all-mldsa44'),('FN-DSA-512','all-fndsa512'),
 ('Hyb(Ed,ML-44)','hybrid-ed-mldsa44'),('Hyb(Ed,FN-512)','hybrid-ed-fndsa512'),
 ('Mixed* (ours)','mixed-mldsa87-root-fn'),('Mixed-SLH','mixed-slh128s-root-fn')]
def maxfit(p,kib):
    d=psize[psize.profile==p]
    b=np.polyfit(d.n,d.size_bytes,1)[0]
    a=d[d.n==0].size_bytes.values[0]
    lim=kib*1024
    if a>lim: return -1
    return int(min(20,np.floor((lim-a)/b)))
def vmed(p,n):
    return pver[(pver.profile==p)&(pver.n==n)].ns.median()/1000.0
C=[r'\begin{table}[t]',r'\centering\small',
 r'\caption{Deployment profiles. Sealed size at ten and twenty hops, whole-chain verification at twenty hops, and the maximum chain length fitting a $4/8/16$\,KiB cookie/header budget ($-1$: even the authority token exceeds it).}',
 r'\label{tab:depprof}',r'\begin{tabular}{lrrrrrr}',r'\hline',
 r'Profile & $S_{10}$ & $S_{20}$ & $V_{20}$ & 4\,KiB & 8\,KiB & 16\,KiB\\',r'\hline']
for disp,p in prof_order:
    s10=psize[(psize.profile==p)&(psize.n==10)].size_bytes.values[0]/1024
    s20=psize[(psize.profile==p)&(psize.n==20)].size_bytes.values[0]/1024
    C.append(f'{disp} & {s10:.1f} & {s20:.1f} & {vmed(p,20):.0f} & {maxfit(p,4)} & {maxfit(p,8)} & {maxfit(p,16)} \\\\')
C += [r'\hline',r'\end{tabular}',r'\end{table}']
open(OUT+'/table_prof.tex','w').write('\n'.join(C))
print('wrote table_micro.tex, table_net.tex, table_prof.tex to',OUT)
