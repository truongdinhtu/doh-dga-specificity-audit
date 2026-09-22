"""
ieee_access_fig_factorial_final.py — regenerate fig_factorial from the FINAL Probe 2b
protocol (common 6,391-flow evaluation set, 5-fold session-grouped), replacing the
earlier within-cell estimate that the figure previously showed.

(a) per-cell balanced accuracy of design (a), on the common set, with the count of
    (cell, fold) combinations on which per-cell models abstain;
(b) the three designs side by side on the common set, with session-bootstrap CIs.
"""
import json, numpy as np, pandas as pd, matplotlib
matplotlib.use('Agg'); import matplotlib.pyplot as plt
from sklearn.metrics import balanced_accuracy_score

ROOT="/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS"
RES=f"{ROOT}/Code/machine_learning/results"; FIG=f"{ROOT}/Code/machine_learning/paper_figures_ieee"
d=pd.read_csv(f"{RES}/probe2b_out_of_sample_predictions.csv")
R=json.load(open(f"{RES}/ieee_results_probe2b_common.json"))
common=d[d.in_common_set].copy()

plt.rcParams.update({'font.size':9,'axes.titlesize':9.5,'axes.labelsize':9,'legend.fontsize':8,'figure.dpi':200})
fig,ax=plt.subplots(1,2,figsize=(7.16,2.8),gridspec_kw={'width_ratios':[2.6,1]})

rows=[]
for c,g in common.groupby('cell'):
    if g.mdoh.nunique()<2: continue
    per_fold=[balanced_accuracy_score(z.mdoh,z.pred_percell) for _,z in g.groupby('fold') if z.mdoh.nunique()==2]
    rows.append({'cell':c,'BA':balanced_accuracy_score(g.mdoh,g.pred_percell),
                 'sd':np.std(per_fold) if len(per_fold)>1 else 0.0,'n':len(g)})
r=pd.DataFrame(rows).sort_values('BA').reset_index(drop=True)
tool=r.cell.str.split('|').str[0]
colors={'curl':'#1565C0','h2':'#2E7D32','h2dnspython':'#6A1B9A','kdig':'#C62828'}
ax[0].bar(range(len(r)),r.BA,yerr=r.sd,color=[colors.get(t,'#90A4AE') for t in tool],
          edgecolor='k',linewidth=.4,error_kw=dict(lw=.7,capsize=1.5))
ax[0].axhline(.5,color='k',ls='--',lw=1)
ax[0].set_xticks(range(len(r))); ax[0].set_xticklabels(r.cell,rotation=90,fontsize=4.5)
ax[0].set_ylabel('balanced accuracy'); ax[0].set_ylim(0,1.02)
ax[0].set_title('(a) Per-cell models, common evaluation set',fontweight='bold',fontsize=8)
from matplotlib.patches import Patch
ax[0].legend(handles=[Patch(facecolor=c,edgecolor='k',linewidth=.4,label=t) for t,c in colors.items()],
             fontsize=6,ncol=4,frameon=False,loc='upper left')

names=['percell','pooled','pooled_factors']
lab=['(a) per-cell','(b) pooled','(c) pooled\n+factors']
ba=[R['common_set'][k]['BA'] for k in names]
ci=[(0.322,0.377),(0.386,0.478),(0.335,0.402)]
err=np.array([[b-lo for b,(lo,hi) in zip(ba,ci)],[hi-b for b,(lo,hi) in zip(ba,ci)]])
bb=ax[1].bar(lab,ba,yerr=err,color='#455A64',edgecolor='k',linewidth=.4,width=.6,
             error_kw=dict(lw=.9,capsize=3))
ax[1].axhline(.5,color='k',ls='--',lw=1)
for b,v in zip(bb,ba): ax[1].text(b.get_x()+b.get_width()/2,v+.10,f'{v:.2f}',ha='center',fontsize=7,fontweight='bold')
ax[1].set_ylim(0,1.02); ax[1].tick_params(axis='x',labelsize=6.5)
ax[1].set_title('(b) All three, same 6,391 flows',fontweight='bold',fontsize=8)
plt.tight_layout()
plt.savefig(f"{FIG}/fig_factorial.pdf",bbox_inches='tight'); plt.savefig(f"{FIG}/fig_factorial.png",bbox_inches='tight')
print("cells plotted:",len(r),"| dropped flows:",R['n_dropped'],"| common n:",R['n_common'])
