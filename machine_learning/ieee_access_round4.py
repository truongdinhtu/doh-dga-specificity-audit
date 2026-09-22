"""
ieee_access_round4.py — Phase A fixes after the third pre-submission review.

  E21  LOFO strict: held-out family removed from ALL sources (incl. generated Zloader)
  E22  Adversarial redo: base flows from TEST partition only, non-negative padding,
       conditional ASR, defense augmented on TRAIN partition only
  E23  Model-B without alidns; metadata-only baseline for Model-T
  E24  Proper length matching (histogram on log10 packets) generated vs sandbox
  E25  Per-cell BA bootstrap CI over cells; positive-class / AUC direction sanity check

Writes results/ieee_results_round4.json.
"""
import warnings; warnings.filterwarnings('ignore')
import os, glob, json
import numpy as np, pandas as pd, lightgbm as lgb
from sklearn.model_selection import train_test_split, StratifiedGroupKFold
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import f1_score, precision_score, recall_score, balanced_accuracy_score, roc_auc_score

ROOT="/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS"
DATA=f"{ROOT}/Code/data/csv/generated"; HKD=f"{ROOT}/Code/data/csv_from_pcap/malicious/HKD"
RES=f"{ROOT}/Code/machine_learning/results"
F6=["mean_Bpp_ab","mean_Bpp_ba","mean_pps_ab","mean_pps_ba","mean_pkts_asm","mean_bytes_asm"]
R={}
d=pd.read_csv(f"{DATA}/s2_mdoh.csv")
d['fam']=d.p_type.str.replace(r'_\d+$','',regex=True)
br=d[d.p_type=='browser']; tools=d[d.p_type.isin(['tool_1','tool_2'])]; mal=d[d.mdoh==1]

def load_hkd():
    out=[]
    for f in sorted(glob.glob(f"{HKD}/*.csv")):
        h=pd.read_csv(f); h=h[(h.dport==443)|(h.sport==443)]
        Bab=h.sum_paysize_ab+h.sum_ip_header_len_ab+h.sum_trans_header_len_ab
        Bba=h.sum_paysize_ba+h.sum_ip_header_len_ba+h.sum_trans_header_len_ba; dur=h.duration/1e6
        o=pd.DataFrame({'mean_Bpp_ab':Bab/h.num_packets_ab,'mean_Bpp_ba':Bba/h.num_packets_ba,
            'mean_pps_ab':h.num_packets_ab/dur,'mean_pps_ba':h.num_packets_ba/dur,
            'mean_pkts_asm':h.num_packets_ba/(h.num_packets_ab+h.num_packets_ba),'mean_bytes_asm':Bba/(Bab+Bba),
            'pkts_aggr':h.num_packets,'pkts_ab':h.num_packets_ab,'bytes_ba':Bba})
        o['family']=os.path.basename(f).split('-')[0]; out.append(o)
    return pd.concat(out,ignore_index=True).replace([np.inf,-np.inf],np.nan).dropna().reset_index(drop=True)
hkd=load_hkd()

def fit(X,y,seed=42):
    sc=RobustScaler(quantile_range=(5,95))
    m=lgb.LGBMClassifier(objective='binary',num_leaves=63,n_estimators=300,learning_rate=0.05,random_state=seed,verbosity=-1)
    m.fit(pd.DataFrame(sc.fit_transform(X[F6]),columns=F6),y); return m,sc
def P(m,sc,X): return m.predict(pd.DataFrame(sc.transform(X[F6].fillna(0)),columns=F6))
def met(y,p): return {'F1':round(f1_score(y,p),4),'Precision':round(precision_score(y,p),4),'Recall':round(recall_score(y,p),4),'BA':round(balanced_accuracy_score(y,p),4)}

# ═════════ E21 LOFO strict ═════════
print("[E21] LOFO strict")
dT=pd.concat([br,tools,mal],ignore_index=True)
E21={}
for fam in sorted(hkd.family.unique()):
    for variant in ['source-holdout','family-holdout']:
        gen=dT if variant=='source-holdout' else dT[dT.fam!=fam]
        tr_r=hkd[hkd.family!=fam]; te_r=hkd[hkd.family==fam]
        X=pd.concat([gen[F6].fillna(0),tr_r[F6]],ignore_index=True)
        y=pd.concat([gen.mdoh.astype(int),pd.Series(np.ones(len(tr_r),int))],ignore_index=True)
        m,sc=fit(X,y)
        E21[f"{fam}|{variant}"]={'heldout_recall':round(float(P(m,sc,te_r).mean()),4),'n_heldout':int(len(te_r)),
            'generated_rows_of_family_in_train':int((gen.fam==fam).sum())}
        print(f"   {fam:<9} {variant:<15} recall={E21[f'{fam}|{variant}']['heldout_recall']:.4f}  gen-{fam}-in-train={E21[f'{fam}|{variant}']['generated_rows_of_family_in_train']}")
strict=[v['heldout_recall'] for k,v in E21.items() if 'family-holdout' in k]
R['E21_lofo']=E21|{'macro_mean_family_holdout':round(float(np.mean(strict)),4),
                   'macro_mean_source_holdout':round(float(np.mean([v['heldout_recall'] for k,v in E21.items() if 'source-holdout' in k])),4)}

# ═════════ E22 Adversarial redo ═════════
print("\n[E22] Adversarial redo (test-partition base flows, non-negative padding, conditional ASR)")
d2=pd.concat([br,mal],ignore_index=True)
X2,y2=d2[F6].fillna(0),d2.mdoh.astype(int)
idx_tr,idx_te=train_test_split(np.arange(len(d2)),test_size=.2,stratify=y2,random_state=42)
tr,te=d2.iloc[idx_tr],d2.iloc[idx_te]
mB,scB=fit(tr[F6].fillna(0),tr.mdoh.astype(int))
ben_tr=tr[tr.mdoh==0].mean_Bpp_ab; MU,SD=ben_tr.mean(),ben_tr.std()
mal_te=te[te.mdoh==1].copy()

def pad(df,target_mu,seed):
    rng=np.random.default_rng(seed); o=df.copy()
    tgt=rng.normal(target_mu,SD*.5,len(o)).clip(60,400)
    o['mean_Bpp_ab']=np.maximum(tgt,o.mean_Bpp_ab)          # padding cannot shrink a packet
    Bab=o.mean_Bpp_ab*o.pkts_ab; o['mean_bytes_asm']=o.bytes_ba/(Bab+o.bytes_ba)
    o['_padded_bytes_per_pkt']=o.mean_Bpp_ab-df.mean_Bpp_ab; return o

def asr(m,sc,base,adv):
    p0=P(m,sc,base); p1=P(m,sc,adv); det=(p0==1)
    return {'ASR_conditional':round(float((p1[det]==0).mean()),4),'n_detected_base':int(det.sum()),
            'FNR_after':round(float((p1==0).mean()),4),'FNR_before':round(float((p0==0).mean()),4),
            'mean_added_bytes_per_pkt':round(float(adv['_padded_bytes_per_pkt'].mean()),2),
            'frac_zero_padding':round(float((adv['_padded_bytes_per_pkt']<=0).mean()),4)}
E22={'n_base_test_malicious':int(len(mal_te)),'benign_ref_train':{'mu':round(float(MU),2),'sd':round(float(SD),2)}}
adv155=pad(mal_te,MU,99)
E22['modelB_shap_aware']=asr(mB,scB,mal_te,adv155); print("   Model-B:",E22['modelB_shap_aware'])
# defense: augment TRAIN malicious only
mal_tr=tr[tr.mdoh==1]; aug=pad(mal_tr,MU,7)
Xa=pd.concat([tr[F6].fillna(0),aug[F6]],ignore_index=True); ya=pd.concat([tr.mdoh.astype(int),pd.Series(np.ones(len(aug),int))],ignore_index=True)
mA,scA=fit(Xa,ya)
E22['hardened_in_domain']=met(te.mdoh.astype(int),P(mA,scA,te))
E22['hardened_shap_aware']=asr(mA,scA,mal_te,adv155); print("   hardened:",E22['hardened_in_domain'],E22['hardened_shap_aware'])
E22['adaptive']={}
for t in [120,130,155,180,200]:
    a=pad(mal_te,t,t); E22['adaptive'][t]={'modelB':asr(mB,scB,mal_te,a)['ASR_conditional'],'hardened':asr(mA,scA,mal_te,a)['ASR_conditional']}
print("   adaptive:",E22['adaptive'])
# Model-R and matched model under the same protocol
XR=pd.concat([dT[F6].fillna(0),hkd[F6]],ignore_index=True); yR=pd.concat([dT.mdoh.astype(int),pd.Series(np.ones(len(hkd),int))],ignore_index=True)
mR,scR=fit(XR,yR); E22['modelR_shap_aware']=asr(mR,scR,mal_te,adv155); print("   Model-R:",E22['modelR_shap_aware'])
R['E22_adversarial']=E22

# ═════════ E23 alidns + metadata baseline ═════════
print("\n[E23] alidns removal; metadata-only baseline")
d2n=d2[d2.doh_server!='alidns']
Xn,yn=d2n[F6].fillna(0),d2n.mdoh.astype(int)
Xtr,Xte,ytr,yte=train_test_split(Xn,yn,test_size=.2,stratify=yn,random_state=42)
m,sc=fit(Xtr,ytr); E23={'modelB_no_alidns':met(yte,P(m,sc,Xte))|{'n':int(len(d2n)),'alidns_removed':int(len(d2)-len(d2n)),
    'alidns_benign':int(((d2.doh_server=='alidns')&(d2.mdoh==0)).sum()),'alidns_malicious':int(((d2.doh_server=='alidns')&(d2.mdoh==1)).sum())}}
print("   Model-B without alidns:",E23['modelB_no_alidns'])
# metadata rule on Model-T composition, evaluated on the same 80/20 split as Model-T
XT,yT,cT=dT[F6].fillna(0),dT.mdoh.astype(int),(dT.p_type!='browser').astype(int)
_,_,_,yTte,_,cTte=train_test_split(XT,yT,cT,test_size=.2,stratify=yT,random_state=42)
E23['metadata_rule_modelT_split']=met(yTte,cTte.values)
E23['metadata_rule_full']={'F1':round(2*len(mal)/(2*len(mal)+len(tools)),4)}
print("   metadata rule (browser->benign, CLI->malicious):",E23['metadata_rule_modelT_split'],E23['metadata_rule_full'])
R['E23']=E23

# ═════════ E24 Proper length matching ═════════
print("\n[E24] Histogram matching on log10(packets) generated vs sandbox")
bins=np.arange(1.0,4.2,0.2)
g=d2.assign(lp=np.log10(d2.pkts_aggr.clip(lower=1))); s=hkd.assign(lp=np.log10(hkd.pkts_aggr.clip(lower=1)))
hg=np.histogram(g.lp,bins)[0]; hs=np.histogram(s.lp,bins)[0]
gm,sm=[],[]
for i in range(len(bins)-1):
    k=min(hg[i],hs[i])
    if k==0: continue
    lo,hi=bins[i],bins[i+1]
    gm.append(g[(g.lp>=lo)&(g.lp<hi)].sample(n=k,random_state=42)); sm.append(s[(s.lp>=lo)&(s.lp<hi)].sample(n=k,random_state=42))
gm=pd.concat(gm); sm=pd.concat(sm)
E24={'n_matched_each':int(len(gm)),'gen_matched_classes':gm.mdoh.value_counts().to_dict(),
     'gen_matched_pkts_median':float(gm.pkts_aggr.median()),'sandbox_matched_pkts_median':float(sm.pkts_aggr.median()),
     'sandbox_matched_families':sm.family.value_counts().to_dict(),
     'support_overlap_fraction_sandbox':round(float(len(sm)/len(s)),4)}
E24['modelB_full_on_matched_sandbox']=round(float(P(mB,scB,sm).mean()),4)
if gm.mdoh.nunique()==2 and (gm.mdoh==0).sum()>=30 and (gm.mdoh==1).sum()>=30:
    mm,scm=fit(gm[F6].fillna(0),gm.mdoh.astype(int))
    E24['modelB_trained_on_matched_gen']={'recall_matched_sandbox':round(float(P(mm,scm,sm).mean()),4),
        'recall_all_sandbox':round(float(P(mm,scm,hkd).mean()),4)}
R['E24_length_matched']=E24; print("  ",E24)

# ═════════ E25 per-cell CI + direction sanity ═════════
print("\n[E25] Per-cell bootstrap CI; positive-class sanity")
r3=json.load(open(f"{RES}/ieee_results_round3.json"))
cells=np.array([v['BA'] for v in r3['E15_factorial']['cells'].values()])
rng=np.random.default_rng(0); bs=[rng.choice(cells,len(cells),replace=True).mean() for _ in range(5000)]
E25={'cell_mean_BA':round(float(cells.mean()),4),'cell_mean_BA_ci95':[round(float(np.percentile(bs,2.5)),4),round(float(np.percentile(bs,97.5)),4)],
     'n_cells':int(len(cells))}
# direction sanity: on pooled CLI conditioned set, confirm classes_ and that AUC uses P(y=1)
sub=pd.concat([tools,mal.sample(n=len(tools),random_state=42)],ignore_index=True)
X,y,gg=sub[F6].fillna(0),sub.mdoh.astype(int),sub.file_name
aucs=[];
for trn,tst in StratifiedGroupKFold(n_splits=5,shuffle=True,random_state=42).split(X,y,groups=gg):
    sc=RobustScaler(quantile_range=(5,95)); m=lgb.LGBMClassifier(objective='binary',num_leaves=63,n_estimators=300,learning_rate=0.05,random_state=42,verbosity=-1,class_weight='balanced')
    m.fit(pd.DataFrame(sc.fit_transform(X.iloc[trn]),columns=F6),y.iloc[trn])
    pr=m.predict_proba(pd.DataFrame(sc.transform(X.iloc[tst]),columns=F6))
    pos=list(m.classes_).index(1); aucs.append(roc_auc_score(y.iloc[tst],pr[:,pos]))
E25['direction_check']={'classes_':[int(c) for c in m.classes_],'pos_index':pos,'AUC_pooled_client':round(float(np.mean(aucs)),4),
    'AUC_if_scores_flipped':round(float(1-np.mean(aucs)),4)}
R['E25']=E25; print("  ",E25)

json.dump(R,open(f"{RES}/ieee_results_round4.json",'w'),indent=2,default=str); print("\nSaved.")
