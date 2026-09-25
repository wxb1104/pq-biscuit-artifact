import pandas as pd, os
D=os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','data')
OUT=os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','analysis')

def b64_padded(n): return 4*((n+2)//3)
def b64url_nopad(n):
    r=n%3
    if r==0: return 4*(n//3)
    if r==1: return 4*(n//3)+2
    return 4*(n//3)+3

PREFIX=len('Authorization: Bearer ')  # 22
CRLF=2
df=pd.read_csv(os.path.join(D,'e55_token_size.csv'))
rows=[]
for (alg,n),g in df.groupby(['alg','n']):
    raw=int(g.sealed_bytes.iloc[0])
    b64=b64_padded(raw); b64u=b64url_nopad(raw)
    hdr_b64u=PREFIX+b64u+CRLF
    hdr_b64=PREFIX+b64+CRLF
    rows.append(dict(alg=alg,n=n,raw=raw,b64url=b64u,b64=b64,hdr_b64url=hdr_b64u,hdr_b64=hdr_b64))
b=pd.DataFrame(rows); b.to_csv(os.path.join(OUT,'ci_budget.csv'),index=False)
print('PREFIX len =',PREFIX)
print('\nn20 wire/header budget (bytes):')
n20=b[b.n==20].sort_values('raw')
for _,x in n20.iterrows():
    print(f"  {x.alg:>14} raw={x.raw:7} b64url={x.b64url:7} AuthzHdr={x.hdr_b64url:7}")
print('\nkey n points (raw / b64url / Authz header):')
for alg in ['Ed25519','Mldsa87','Fndsa512','Slhdsa128f']:
    for n in [1,10,20]:
        x=b[(b.alg==alg)&(b.n==n)].iloc[0]
        print(f"  {alg:>12} n{n:<2} raw={x.raw:7} b64url={x.b64url:7} hdr={x.hdr_b64url:7}")
