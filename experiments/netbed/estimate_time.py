#!/usr/bin/env python3
import csv
NB="/mnt/e/pqc+zhengshu/biscuit-pq/experiments/netbed"
DATA="/mnt/e/pqc+zhengshu/biscuit-pq/experiments/data"
man={}
with open(NB+"/net_tokens_manifest.csv") as f:
    for r in csv.DictReader(f):
        man[(r["profile"],int(r["n"]))]=int(r["b64_b"])
tp=0
with open(DATA+"/net_throughput.csv") as f:
    tp=sum(1 for _ in f)-1
EN3_TOTAL=432; DUR=15
rem=EN3_TOTAL-tp
en3=rem*DUR+rem*0.6
NB_PROFS="ed25519 fndsa512 mldsa87 slhdsa128f hyb-ed-fndsa512 mix-mldsa87-fndsa512".split()
def en4(bps,S):
    tot=0
    for p in NB_PROFS:
        for n in (10,20):
            sup=man[(p,n)]+90
            tot+=S*(sup/bps+0.05)
    return tot
en4_1=en4(125000,30); en4_46=en4(5750,20)
en5=60*8; en6=180; patch=240
def mm(x): return f"{int(x//60)}m{int(x%60)}s"
print(f"en3 remaining: {mm(en3)}  ({tp}/432 done)")
print(f"en4 1mbit: {mm(en4_1)}   en4 46kbit: {mm(en4_46)}")
print(f"en5: {mm(en5)}  en6: {mm(en6)}  patch: {mm(patch)}")
tot=en3+en4_1+en4_46+en5+en6+patch
print(f"TOTAL remaining: {mm(tot)} = {tot/3600:.2f} h")
print("46kbit per-profile:")
for p in NB_PROFS:
    line=[]
    for n in (10,20):
        sup=man[(p,n)]+90
        line.append(f"n{n}:{mm(20*(sup/5750+0.05))}")
    print("  ",p," ".join(line))
