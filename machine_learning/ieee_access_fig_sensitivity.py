"""
ieee_access_fig_sensitivity.py — Appendix figure (fig_evasion.pdf) drawn ONLY from the
data behind Table 17 (results/ieee_results_round6.json, E33_adversarial_fair) and
Table 18 (results/ieee_results_round4.json, adaptive). Packet-insertion strategies are
not drawn: their base split is not recorded and they are not comparable.
"""
import json, numpy as np, matplotlib
matplotlib.use('Agg'); import matplotlib.pyplot as plt
ROOT="/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS"
RES=f"{ROOT}/Code/machine_learning/results"; OUT=f"{ROOT}/Submit_IEEEAccess/Figures"
plt.rcParams.update({'font.size':7.5,'font.family':'serif','axes.linewidth':.6})

E33=json.load(open(f"{RES}/ieee_results_round6.json"))['E33_adversarial_fair']
R4=json.load(open(f"{RES}/ieee_results_round4.json"))
def find(o,key):
    if isinstance(o,dict):
        if key in o: return o[key]
        for v in o.values():
            r=find(v,key)
            if r is not None: return r
    return None
adaptive=find(R4,'adaptive'); hs=find(R4,'hardened_shap_aware')

fig,ax=plt.subplots(1,2,figsize=(7.16,2.5))
# (a) added bytes vs DFR, Table 17
uni=[(E33[k]['added_bytes_per_pkt_mean'],E33[k]['ASR_conditional']*100) for k in
     ['uniform_+20B','uniform_+40B','uniform_+60B','uniform_+80B','uniform_+120B']]
ax[0].plot([u[0] for u in uni],[u[1] for u in uni],'-o',color='#37474F',ms=4,lw=1,label='uniform increment')
b=E33['block_padding_128']; g=E33['shap_aware_gaussian_155']
ax[0].plot(b['added_bytes_per_pkt_mean'],b['ASR_conditional']*100,'s',color='#EF6C00',ms=5,label='128-B block approx. (flow mean)')
ax[0].plot(g['added_bytes_per_pkt_mean'],g['ASR_conditional']*100,'^',color='#6A1B9A',ms=5,label='attribution-informed, target 155')
ax[0].set_xlabel('mean added client payload (B/pkt)'); ax[0].set_ylabel('decision-flip rate, DFR (%)')
ax[0].set_ylim(0,105); ax[0].set_xlim(0,130); ax[0].legend(fontsize=6.3,loc='lower right')
ax[0].set_title('(a) Model-B, same 4,799 base flows',fontweight='bold',fontsize=8)
# (b) hardening across targets, Table 18
t=sorted(adaptive,key=int); x=np.arange(len(t)); w=.36
before=[adaptive[k]['modelB']*100 for k in t]; after=[adaptive[k]['hardened']*100 for k in t]
ax[1].bar(x-w/2,before,w,label='Model-B',color='#C62828',edgecolor='k',linewidth=.4)
ax[1].bar(x+w/2,after,w,label='hardened',color='#2E7D32',edgecolor='k',linewidth=.4)
for i,(vb,va) in enumerate(zip(before,after)):
    ax[1].text(i-w/2,vb+1.5,f'{vb:.1f}',ha='center',fontsize=6)
    ax[1].text(i+w/2,va+1.5,f'{va:.2f}',ha='center',fontsize=6)
ax[1].set_xticks(x); ax[1].set_xticklabels(t); ax[1].set_xlabel('Gaussian padding target (B/pkt)')
ax[1].set_ylabel('DFR (%)'); ax[1].set_ylim(0,128); ax[1].legend(fontsize=7,loc='upper center',ncol=2,frameon=False)
ax[1].set_title('(b) Before and after hardening',fontweight='bold',fontsize=8)
plt.tight_layout()
plt.savefig(f"{OUT}/fig_evasion.pdf",bbox_inches='tight'); plt.savefig(f"{OUT}/fig_evasion.png",dpi=200,bbox_inches='tight')
print('written',OUT+'/fig_evasion.pdf'); print('table17 rows:',{k:round(v['ASR_conditional']*100,2) for k,v in E33.items()}); print('table18:',{k:(round(v['modelB']*100,2),round(v['hardened']*100,2)) for k,v in adaptive.items()})
