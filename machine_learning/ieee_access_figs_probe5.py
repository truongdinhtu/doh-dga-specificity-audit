"""
ieee_access_figs_probe5.py — regenerate fig_confound and fig_feature_dist with the
OS-level DoH client (Probe 5) added as a traffic source, split by resolver session
because Cloudflare/Google (long, few flows) and Quad9 (short, many flows) are not the
same unit of measurement; pooling them would let Quad9's flow count dominate silently.
Reads only saved results (ieee_results*.json) and deposited flow CSVs; fits no models.
"""
import json, numpy as np, pandas as pd, matplotlib
matplotlib.use('Agg'); import matplotlib.pyplot as plt

ROOT="/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS"; DATA=f"{ROOT}/Code/data/csv/generated"
RES=f"{ROOT}/Code/machine_learning/results"; FIG=f"{ROOT}/Code/machine_learning/paper_figures_ieee"
F6=["mean_Bpp_ab","mean_Bpp_ba","mean_pps_ab","mean_pps_ba","mean_pkts_asm","mean_bytes_asm"]
LBL={"mean_Bpp_ab":r"$\overline{B^{pp}_{ab}}$","mean_Bpp_ba":r"$\overline{B^{pp}_{ba}}$","mean_pps_ab":r"$\overline{pps}_{ab}$",
     "mean_pps_ba":r"$\overline{pps}_{ba}$","mean_pkts_asm":r"$\overline{A}_{pkt}$","mean_bytes_asm":r"$\overline{A}_{byte}$"}
C={'browser':'#2E7D32','tools':'#1565C0','sim':'#C62828','real':'#6A1B9A',
   'cf':'#EF6C00','goog':'#FFA726','q9':'#8D6E63'}
SESS=[('cloudflare_1','Cloudflare','cf'),('google_1','Google','goog'),('quad9_1','Quad9','q9')]

d=pd.read_csv(f"{DATA}/s2_mdoh.csv"); br=d[d.p_type=='browser']; tools=d[d.p_type.isin(['tool_1','tool_2'])]; mal=d[d.mdoh==1]
sb=pd.read_csv(f"{ROOT}/Code/data/csv_from_pcap/malicious/HKD_tranalyzer/sandbox_tranalyzer_L7_18features.csv")
osc=pd.read_csv(f"{ROOT}/Code/data/csv_from_pcap/os_doh_client/os_doh_client_L7_flows.csv")
osc=osc[~osc.label_contaminated]  # exclude flows whose traffic spans into a different-label block
R=json.load(open(f"{RES}/ieee_results.json")); PB=json.load(open(f"{RES}/ieee_results_phaseB.json")); P5=json.load(open(f"{RES}/ieee_results_os_doh_client.json"))

plt.rcParams.update({'font.size':9,'axes.titlesize':9.5,'axes.labelsize':9,'legend.fontsize':8,'figure.dpi':200})

# Fig — the confound
fig,ax=plt.subplots(1,3,figsize=(7.16,2.6))
groups=[('Browser\nbenign',br.mean_Bpp_ab,C['browser']),('Tools\nbenign',tools.mean_Bpp_ab,C['tools']),('Sim.\nDGA',mal.mean_Bpp_ab,C['sim']),
        ('Sandbox\nmalware',sb.mean_Bpp_ab,C['real'])]
for sid,name,ckey in SESS:
    g=osc[(osc.session==sid)&(osc.label=='benign')]
    groups.append((f'OS {name}\nbenign',g.mean_Bpp_ab,C[ckey]))
bp=ax[0].boxplot([g[1].clip(0,400) for g in groups],labels=[g[0].replace(chr(10),' ') for g in groups],patch_artist=True,showfliers=False,medianprops=dict(color='k',linewidth=1.2),widths=.6)
for patch,g in zip(bp['boxes'],groups): patch.set_facecolor(g[2]); patch.set_alpha(.65)
ax[0].axhspan(60,100,color='grey',alpha=.12); ax[0].set_ylabel(r'$\overline{B^{pp}_{ab}}$  (B/pkt)')
ax[0].set_title('(a) Dominant feature',fontweight='bold',fontsize=8)
ax[0].set_xticklabels(ax[0].get_xticklabels(),rotation=35,ha='right',fontsize=5.5)
sh=pd.Series(R['shap_s2']['share'])[F6]
ax[1].barh([LBL[f] for f in F6][::-1],sh.values[::-1]*100,color=['#B0BEC5']*5+[C['sim']],edgecolor='k',linewidth=.4)
ax[1].set_xlabel('share of mean $|\\phi_i|$  (%)',fontsize=8); ax[1].set_title('(b) SHAP concentration',fontweight='bold',fontsize=8)
for i,v in enumerate(sh.values[::-1]): ax[1].text(v*100+1,i,f'{v*100:.1f}',va='center',fontsize=7)
ax[1].set_xlim(0,85)

bars=['Sim. DGA (test)','Benign tools (FPR)','Sandbox mal. (recall)','OS Cloudflare (FPR)','OS Google (FPR)','OS Quad9 (FPR)']
vals=[R['stage2_baseline']['Recall'],R['fpr_tools']['fpr'],PB['E26_modelB_L7']['micro']]
cols=[C['sim'],C['tools'],C['real']]
for sid,name,ckey in SESS:
    vals.append(P5['E39_per_session'][sid]['FPR_benign']); cols.append(C[ckey])
bb=ax[2].bar(bars,[v*100 for v in vals],color=cols,edgecolor='k',linewidth=.4,width=.6)
for b,v in zip(bb,vals): ax[2].text(b.get_x()+b.get_width()/2,v*100+2,f'{v*100:.1f}',ha='center',fontsize=5.8,fontweight='bold')
ax[2].set_ylabel('classified as malicious (%)'); ax[2].set_ylim(0,115); ax[2].set_title('(c) Model-B by source',fontweight='bold',fontsize=8)
ax[2].set_xticklabels(bars,rotation=45,ha='right',fontsize=5.3)
plt.tight_layout(); plt.savefig(f"{FIG}/fig_confound.pdf",bbox_inches='tight'); plt.savefig(f"{FIG}/fig_confound.png",bbox_inches='tight'); plt.close()

# Fig — feature distributions. Cloudflare/Google (few flows) shown as a rug; Quad9 (233
# benign flows, enough for a real density) shown as a step histogram like the other sources.
fig,axes=plt.subplots(2,3,figsize=(7.16,3.6))
q9b=osc[(osc.session=='quad9_1')&(osc.label=='benign')]
for a,f in zip(axes.ravel(),F6):
    for lab,s,c in [('browser',br[f],C['browser']),('tools',tools[f],C['tools']),('sim. DGA',mal[f],C['sim']),
                     ('sandbox mal.',sb[f],C['real']),('OS Quad9 benign',q9b[f],C['q9'])]:
        v=s.replace([np.inf,-np.inf],np.nan).dropna(); lo,hi=np.percentile(v,[1,99])
        a.hist(v.clip(lo,hi),bins=40,density=True,histtype='step',lw=1.1,color=c,label=lab)
    for sid,name,ckey in [('cloudflare_1','Cloudflare','cf'),('google_1','Google','goog')]:
        v=osc[(osc.session==sid)&(osc.label=='benign')][f].replace([np.inf,-np.inf],np.nan).dropna()
        for x in v: a.axvline(x,color=C[ckey],lw=.8,alpha=.7)
        a.plot([],[],color=C[ckey],lw=.8,label=f'OS {name} benign (n={len(v)})')
    a.set_title(LBL[f],fontsize=8); a.set_yticks([]); a.tick_params(labelsize=6)
axes[0,0].legend(fontsize=4.3,loc='upper right')
plt.tight_layout(); plt.savefig(f"{FIG}/fig_feature_dist.pdf",bbox_inches='tight'); plt.savefig(f"{FIG}/fig_feature_dist.png",bbox_inches='tight'); plt.close()
print("figures written to",FIG)
