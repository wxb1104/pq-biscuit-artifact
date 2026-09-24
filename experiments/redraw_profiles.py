import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd
import figstyle as fs
fs.setup()

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.path.join(HERE, 'data') + os.sep
OUT = os.path.join(HERE, 'figures', 'profiles.png')
os.makedirs(os.path.dirname(OUT), exist_ok=True)
size=pd.read_csv(D+'e6_profiles_size.csv')
ver=pd.read_csv(D+'e6_profiles_verify.csv').groupby(['profile','n'])['ns'].median().reset_index()

order=['all-ed','all-mldsa44','all-fndsa512','hybrid-ed-mldsa44',
       'hybrid-ed-fndsa512','mixed-mldsa87-root-fn','mixed-slh128s-root-fn']
rec='mixed-mldsa87-root-fn'
lab={'all-ed':'Ed','all-mldsa44':'ML-44','all-fndsa512':'FN-512',
     'hybrid-ed-mldsa44':'Hyb+ML44','hybrid-ed-fndsa512':'Hyb+FN512',
     'mixed-mldsa87-root-fn':'Mixed*','mixed-slh128s-root-fn':'Mixed-SLH'}

fig,(axa,axb)=plt.subplots(1,2,figsize=(6.7,3.0))

def draw(ax,df,col,scale,marker):
    for p in order:
        d=df[df.profile==p].sort_values('n')
        x=d.n.values; y=d[col].values*scale
        bold=p==rec
        ax.plot(x,y,marker=marker,ms=3.6 if bold else 3.2,
                color=fs.color_of(p),lw=2.5 if bold else 1.6,
                zorder=4 if bold else 2)

# (a) size
draw(axa,size,'size_bytes',1/1024,'o')
for b in (4,8):
    axa.axhline(b,color='#9a9a9a',ls=':',lw=1.0,zorder=1)
axa.annotate('4 KiB budget',(0.15,4),xytext=(2,7),textcoords='offset points',
             fontsize=7,color='#808080')
axa.annotate('8 KiB',(0.15,8),xytext=(2,7),textcoords='offset points',
             fontsize=7,color='#808080')
axa.set_yscale('log'); axa.set_xlim(0,26); axa.set_ylim(1.5,120)
axa.set_title('(a) sealed token size vs depth',fontsize=9.6)
axa.set_xlabel('attenuation depth n'); axa.set_ylabel('sealed token size (KiB)')

# (b) verify
draw(axb,ver,'ns',1/1000,'s')
axb.set_xlim(0,26); axb.set_ylim(-60,1980)
axb.set_title('(b) verification latency vs depth (AVX2)',fontsize=9.6)
axb.set_xlabel('attenuation depth n'); axb.set_ylabel('full-chain verification (\u00b5s)')

# realize transforms so transData -> display pixels is valid
fig.canvas.draw()

def auto_labels(ax,df,col,scale,gap=11.6):
    # data end-point display pixels
    items=[]
    for p in order:
        r=df[(df.profile==p)&(df.n==20)]
        if not len(r): continue
        y=float(r[col].iloc[0])*scale
        px,py=ax.transData.transform((20,y))
        items.append([p,px,py])
    items.sort(key=lambda t:t[2])
    # iteratively separate neighbours to >= gap (split the push both ways)
    for _ in range(60):
        moved=False
        for i in range(1,len(items)):
            d=items[i][2]-items[i-1][2]
            if d<gap:
                q=(gap-d)/2
                items[i][2]+=q; items[i-1][2]-=q; moved=True
        if not moved: break
    # keep labels inside the axes vertical bbox
    inv=ax.transData.inverted()
    top=ax.transData.transform((0,ax.get_ylim()[1]))[1]-2
    bot=ax.transData.transform((0,ax.get_ylim()[0]))[1]+2
    ys=[t[2] for t in items]
    if max(ys)>top:
        sh=max(ys)-top
        for t in items: t[2]-=sh
    if min(ys)<bot:
        sh=bot-min(ys)
        for t in items: t[2]+=sh
    for p,px,py in items:
        dpx,dpy=ax.transData.transform(
            (20,float(df[(df.profile==p)&(df.n==20)][col].iloc[0])*scale))
        bold=p==rec
        ax.annotate(lab[p],xy=(dpx,dpy),xytext=(px+6,py),
                    xycoords='figure pixels',textcoords='figure pixels',
                    ha='left',va='center',fontsize=7.6,color=fs.color_of(p),
                    fontweight='bold' if bold else 'normal',clip_on=False,
                    arrowprops=dict(arrowstyle='-',color='#c8c8c8',lw=0.5,
                                    shrinkA=0,shrinkB=2))

auto_labels(axa,size,'size_bytes',1/1024)
auto_labels(axb,ver,'ns',1/1000)

plt.tight_layout()
plt.savefig(OUT,dpi=200,bbox_inches='tight',facecolor='white')
print('saved',OUT)
