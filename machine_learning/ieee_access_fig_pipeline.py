"""
ieee_access_fig_pipeline.py — Fig. 6 (fig_pipeline.pdf), drawn from the rows of Table 13
plus the same-flow byte-layer comparison (3,369 Tranalyzer2 flows, network-layer vs
TCP-payload accounting). Terminology: "network-layer" / "TCP payload", never "L3"/"L7".
"""
import json, matplotlib
matplotlib.use('Agg'); import matplotlib.pyplot as plt
ROOT="/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS"; OUT=f"{ROOT}/Submit_IEEEAccess/Figures"
plt.rcParams.update({'font.size':7.5,'font.family':'serif','axes.linewidth':.6})
rows=[('NetExP\nnet-layer\n2,357',7.81,'#B0BEC5'),
      ('T2\nnet-layer\n3,649',28.53,'#B0BEC5'),
      ('T2\nnet-layer\n3,369*',22.59,'#78909C'),
      ('NetExP\npayload\n2,357',99.11,'#455A64'),
      ('T2\npayload\n3,369*',98.81,'#263238')]
fig,ax=plt.subplots(figsize=(3.5,2.5))
x=range(len(rows))
ax.bar(x,[r[1] for r in rows],color=[r[2] for r in rows],edgecolor='k',linewidth=.4,width=.65)
for i,r in enumerate(rows): ax.text(i,r[1]+2,f'{r[1]:.1f}',ha='center',fontsize=7)
ax.set_xticks(list(x)); ax.set_xticklabels([r[0] for r in rows],fontsize=6.5)
ax.set_ylabel('Model-B recall on sandbox (%)'); ax.set_ylim(0,122)
ax.set_title('Same captures, same model, different extraction',fontsize=8,fontweight='bold')
ax.text(0.02,0.97,'T2 = Tranalyzer2; payload = TCP payload; * = identical 3,369 flows',transform=ax.transAxes,fontsize=6,va='top')
plt.tight_layout(); plt.savefig(f"{OUT}/fig_pipeline.pdf",bbox_inches='tight'); plt.savefig(f"{OUT}/fig_pipeline.png",dpi=200,bbox_inches='tight'); print('ok')
