"""
ieee_access_round6.py — fixes after the fifth pre-submission review.

  E30  Probe 2b on identical outer session splits:
       (a) per-cell models, out-of-sample predictions pooled;
       (b) pooled model, features only;
       (c) pooled model, features + one-hot client/resolver/format;
       per-session metrics; LOCO with session-bootstrap CI
  E31  Table 11 attrition: L3 vs L7 on identical flow IDs
  E32  Probe 1b: paired session-bootstrap CI of the F1 drop; univariate Bpp_ab after matching
  E33  Adversarial: non-SHAP uniform padding baselines on the same base flows, conditional ASR + FNR
  E34  Trivial baselines: always-positive, metadata-only
"""
import warnings; warnings.filterwarnings('ignore')
import os, json, numpy as np, pandas as pd, lightgbm as lgb
from sklearn.model_selection import train_test_split, StratifiedGroupKFold
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import f1_score, balanced_accuracy_score, roc_auc_score, average_precision_score

ROOT="/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS"; DATA=f"{ROOT}/Code/data/csv/generated"
T2=f"{ROOT}/Code/data/csv_from_pcap/malicious/HKD_tranalyzer"; RES=f"{ROOT}/Code/machine_learning/results"
F6=["mean_Bpp_ab","mean_Bpp_ba","mean_pps_ab","mean_pps_ba","mean_pkts_asm","mean_bytes_asm"]
R={}
d=pd.read_csv(f"{DATA}/s2_mdoh.csv"); br=d[d.p_type=='browser']; tools=d[d.p_type.isin(['tool_1','tool_2'])]; mal=d[d.mdoh==1]
def lgbm(seed=42,balanced=False): return lgb.LGBMClassifier(objective='binary',num_leaves=63,n_estimators=300,learning_rate=0.05,random_state=seed,verbosity=-1,class_weight='balanced' if balanced else None)
def fitp(Xtr,ytr,Xte,feats,balanced=False):
    sc=RobustScaler(quantile_range=(5,95)); m=lgbm(balanced=balanced).fit(pd.DataFrame(sc.fit_transform(Xtr[feats]),columns=feats),ytr)
    Z=pd.DataFrame(sc.transform(Xte[feats]),columns=feats); return m.predict(Z),m.predict_proba(Z)[:,1]
def sess_boot(df,fn,n=2000,seed=0):
    rng=np.random.default_rng(seed); g=df.file_name.values; u=np.unique(g); idx={k:np.where(g==k)[0] for k in u}; v=[]
    for _ in range(n):
        pick=rng.choice(u,len(u),replace=True); i=np.concatenate([idx[k] for k in pick])
        try: v.append(fn(df.iloc[i]))
        except Exception: pass
    return [round(float(np.percentile(v,2.5)),4),round(float(np.percentile(v,97.5)),4)]

# ═════════ E30 ═════════
print("[E30] Probe 2b on identical outer session splits")
cli=pd.concat([tools,mal],ignore_index=True)
cli['cell']=cli.p_name+'|'+cli.doh_server+'|'+cli.doh_method
# stratified-balanced within cell (same construction as round 3, 3-factor stratum)
parts=[]
for c,g in cli.groupby('cell'):
    nb,nm=(g.mdoh==0).sum(),(g.mdoh==1).sum()
    if nb<30 or nm<30: continue
    k=min(nb,nm); parts+=[g[g.mdoh==0].sample(n=k,random_state=42),g[g.mdoh==1].sample(n=k,random_state=42)]
sub=pd.concat(parts,ignore_index=True)
oh=pd.get_dummies(sub[['p_name','doh_server','doh_method']],dtype=float); Xf=pd.concat([sub[F6].fillna(0),oh],axis=1); FC=list(Xf.columns)
y=sub.mdoh.astype(int); g=sub.file_name
pred={k:np.full(len(sub),np.nan) for k in ['percell','pooled','pooled_factors']}; prob={k:np.full(len(sub),np.nan) for k in pred}
for tr,te in StratifiedGroupKFold(n_splits=5,shuffle=True,random_state=42).split(Xf,y,groups=g):
    # (b) pooled, features only
    p,pr=fitp(Xf.iloc[tr],y.iloc[tr],Xf.iloc[te],F6,True); pred['pooled'][te]=p; prob['pooled'][te]=pr
    # (c) pooled + factors
    p,pr=fitp(Xf.iloc[tr],y.iloc[tr],Xf.iloc[te],FC,True); pred['pooled_factors'][te]=p; prob['pooled_factors'][te]=pr
    # (a) per-cell models on the same split
    for c in sub.cell.unique():
        trc=tr[sub.cell.values[tr]==c]; tec=te[sub.cell.values[te]==c]
        if len(tec)==0 or y.iloc[trc].nunique()<2: continue
        p,pr=fitp(Xf.iloc[trc],y.iloc[trc],Xf.iloc[tec],F6,True); pred['percell'][tec]=p; prob['percell'][tec]=pr
E30={}
for k in pred:
    ok=~np.isnan(pred[k]); yy=y.values[ok]; pp=pred[k][ok]; qq=prob[k][ok]
    dfk=sub[ok].assign(p=pp,q=qq,y=yy)
    E30[k]={'n':int(ok.sum()),'BA':round(float(balanced_accuracy_score(yy,pp)),4),'AUC':round(float(roc_auc_score(yy,qq)),4),'PR_AUC':round(float(average_precision_score(yy,qq)),4),
            'BA_ci95_session':sess_boot(dfk,lambda z: balanced_accuracy_score(z.y,z.p)),
            'per_cell_BA':{c:round(float(balanced_accuracy_score(z.y,z.p)),4) for c,z in dfk.groupby('cell') if z.y.nunique()==2},
            'per_session_BA_median':round(float(np.median([balanced_accuracy_score(z.y,z.p) for _,z in dfk.groupby('file_name') if z.y.nunique()==2])),4)}
    print(f"   {k:15} n={E30[k]['n']} BA={E30[k]['BA']} CI={E30[k]['BA_ci95_session']} AUC={E30[k]['AUC']} PR={E30[k]['PR_AUC']}  per-cell BA mean={np.mean(list(E30[k]['per_cell_BA'].values())):.4f}")
R['E30_probe2b_same_splits']=E30
# LOCO with session bootstrap CI
print("   LOCO with CI:")
dT=pd.concat([br,tools,mal],ignore_index=True); loco={}
for tool in sorted(tools.p_name.unique()):
    tr=dT[dT.p_name!=tool]; te=dT[dT.p_name==tool]
    p,pr=fitp(tr,tr.mdoh.astype(int),te,F6); dfk=te.assign(p=p,y=te.mdoh.astype(int).values,q=pr)
    loco[tool]={'BA':round(float(balanced_accuracy_score(dfk.y,dfk.p)),4),'BA_ci95_session':sess_boot(dfk,lambda z: balanced_accuracy_score(z.y,z.p)),
                'AUC':round(float(roc_auc_score(dfk.y,dfk.q)),4),'n_sessions':int(te.file_name.nunique())}
    print(f"     {tool:12}",loco[tool])
R['E30_loco_ci']=loco

# ═════════ E31 ═════════
print("\n[E31] Table 11 attrition, same flow IDs")
def rd(p):
    df=pd.read_csv(p,sep='\t'); df.columns=[c.lstrip('%') for c in df.columns]; return df
rows=[]
for fam in ['padcrypt','sisron','tinba','zloader']:
    l3=rd(f"{T2}/{fam}-doh-24h_L3.csv"); l7=rd(f"{T2}/{fam}-doh-24h_L7.csv")
    m=l3.merge(l7[['flowInd','dir','l7BytesSnt']],on=['flowInd','dir'])
    a=m[m.dir=='A'].set_index('flowInd'); b=m[m.dir=='B'].set_index('flowInd'); idx=a.index.intersection(b.index); a,b=a.loc[idx],b.loc[idx]
    o=pd.DataFrame({'flowInd':idx,'family':fam,'dstPort':a.dstPort.values,'dur':(np.maximum(a.timeLast,b.timeLast)-np.minimum(a.timeFirst,b.timeFirst)).values,
        'pab':a.pktsSnt.values,'pba':b.pktsSnt.values,'L3ab':a.l3BytesSnt.values,'L3ba':b.l3BytesSnt.values,'L7ab':a.l7BytesSnt.values,'L7ba':b.l7BytesSnt.values,
        'uni_A_only':len(l3[l3.dir=='A'])-len(idx)})
    rows.append(o)
raw=pd.concat(rows,ignore_index=True)
attr={'A_rows_total':{f:int(rd(f"{T2}/{f}-doh-24h_L3.csv").query("dir=='A'").shape[0]) for f in ['padcrypt','sisron','tinba','zloader']},
      'bidirectional':raw.family.value_counts().to_dict(),'port443':raw[raw.dstPort==443].family.value_counts().to_dict()}
raw=raw[raw.dstPort==443]
zero_pay=(raw.L7ab+raw.L7ba==0); attr['zero_payload_both_dirs']=raw[zero_pay].family.value_counts().to_dict()
attr['L7_valid']=raw[~zero_pay].family.value_counts().to_dict()
common=raw[~zero_pay & (raw.dur>0)]
def feats(o,L):
    Bab,Bba=o[f'{L}ab'],o[f'{L}ba']; dur=o.dur.replace(0,np.nan)
    return pd.DataFrame({'mean_Bpp_ab':Bab/o.pab,'mean_Bpp_ba':Bba/o.pba,'mean_pps_ab':o.pab/dur,'mean_pps_ba':o.pba/dur,'mean_pkts_asm':o.pba/(o.pab+o.pba),'mean_bytes_asm':Bba/(Bab+Bba),'family':o.family}).replace([np.inf,-np.inf],np.nan).dropna()
dB=pd.concat([br,mal],ignore_index=True); X,yb=dB[F6].fillna(0),dB.mdoh.astype(int)
Xtr,Xte,ytr,yte=train_test_split(X,yb,test_size=.2,stratify=yb,random_state=42)
sc=RobustScaler(quantile_range=(5,95)); mB=lgbm().fit(pd.DataFrame(sc.fit_transform(Xtr),columns=F6),ytr)
P=lambda Z: mB.predict(pd.DataFrame(sc.transform(Z[F6]),columns=F6))
f3,f7=feats(common,'L3'),feats(common,'L7')
attr['same_flowIDs']={'n':int(len(common)),'recall_L3':round(float(P(f3).mean()),4),'recall_L7':round(float(P(f7).mean()),4),
    'hdr_bytes_per_pkt_ab_mean':round(float(((common.L3ab-common.L7ab)/common.pab).mean()),2),'hdr_bytes_per_pkt_ab_p10_p90':[round(float(x),2) for x in np.percentile((common.L3ab-common.L7ab)/common.pab,[10,90])]}
R['E31_attrition']=attr; print("  ",json.dumps(attr,indent=1))

# ═════════ E32 ═════════
print("\n[E32] Probe 1b: paired CI and univariate")
i_tr,i_te=train_test_split(np.arange(len(dB)),test_size=.2,stratify=yb,random_state=42); tr,te=dB.iloc[i_tr],dB.iloc[i_te]
bins=np.arange(40,260,10); b=tr[tr.mdoh==0]; m_=tr[tr.mdoh==1]
hb=np.histogram(b.mean_Bpp_ab.clip(40,259),bins)[0]; hm=np.histogram(m_.mean_Bpp_ab.clip(40,259),bins)[0]; pb,pm=[],[]
for i in range(len(bins)-1):
    k=min(hb[i],hm[i])
    if k==0: continue
    lo,hi=bins[i],bins[i+1]; pb.append(b[(b.mean_Bpp_ab>=lo)&(b.mean_Bpp_ab<hi)].sample(n=k,random_state=42)); pm.append(m_[(m_.mean_Bpp_ab>=lo)&(m_.mean_Bpp_ab<hi)].sample(n=k,random_state=42))
M=pd.concat(pb+pm,ignore_index=True)
pB,_=fitp(tr,tr.mdoh.astype(int),te,F6); pM,_=fitp(M,M.mdoh.astype(int),te,F6)
dfk=te.assign(y=te.mdoh.astype(int).values,pB=pB,pM=pM)
diff_ci=sess_boot(dfk,lambda z: f1_score(z.y,z.pB)-f1_score(z.y,z.pM))
# univariate Bpp_ab on matched training set, evaluated on matched grouped CV and on unmatched test
pU,_=fitp(M,M.mdoh.astype(int),te,['mean_Bpp_ab'])
# univariate within matched set (grouped CV)
XM,yM,gM=M[['mean_Bpp_ab']],M.mdoh.astype(int),M.file_name; ba=[]
for trm,tem in StratifiedGroupKFold(n_splits=5,shuffle=True,random_state=42).split(XM,yM,groups=gM):
    p,_=fitp(M.iloc[trm],yM.iloc[trm],M.iloc[tem],['mean_Bpp_ab'],True); ba.append(balanced_accuracy_score(yM.iloc[tem],p))
R['E32_probe1b']={'F1_full':round(float(f1_score(dfk.y,dfk.pB)),4),'F1_matched':round(float(f1_score(dfk.y,dfk.pM)),4),
    'F1_drop':round(float(f1_score(dfk.y,dfk.pB)-f1_score(dfk.y,dfk.pM)),4),'F1_drop_ci95_session':diff_ci,
    'univariate_Bpp_matched_train_BA_on_matched_groupedCV':round(float(np.mean(ba)),4),
    'univariate_Bpp_matched_train_F1_on_unmatched_test':round(float(f1_score(dfk.y,pU)),4)}
print("  ",R['E32_probe1b'])

# ═════════ E33 ═════════
print("\n[E33] Adversarial: fair comparison on same base flows")
mal_te=te[te.mdoh==1].copy(); ben_tr=tr[tr.mdoh==0].mean_Bpp_ab; MU,SD=ben_tr.mean(),ben_tr.std()
def asr(base,adv):
    p0=P(base); p1=P(adv); det=p0==1
    return {'ASR_conditional':round(float((p1[det]==0).mean()),4),'FNR_after':round(float((p1==0).mean()),4),'added_bytes_per_pkt_mean':round(float((adv.mean_Bpp_ab-base.mean_Bpp_ab).mean()),2)}
def apply_pad(df,new_bpp):
    o=df.copy(); o['mean_Bpp_ab']=np.maximum(new_bpp,o.mean_Bpp_ab); Bab=o.mean_Bpp_ab*o.pkts_ab; o['mean_bytes_asm']=o.bytes_ba/(Bab+o.bytes_ba); return o
E33={}
for add in [20,40,60,80,120]:
    E33[f'uniform_+{add}B']=asr(mal_te,apply_pad(mal_te,mal_te.mean_Bpp_ab+add))
rng=np.random.default_rng(99); E33['shap_aware_gaussian_155']=asr(mal_te,apply_pad(mal_te,rng.normal(MU,SD*.5,len(mal_te)).clip(60,400)))
E33['block_padding_128']=asr(mal_te,apply_pad(mal_te,np.ceil(mal_te.mean_Bpp_ab/128)*128))   # RFC 8467 block padding to 128-byte multiples
for k,v in E33.items(): print(f"   {k:26}",v)
R['E33_adversarial_fair']=E33

# ═════════ E34 ═════════
print("\n[E34] Trivial baselines")
sbx=pd.read_csv(f"{T2}/sandbox_tranalyzer_L7_18features.csv")
E34={'always_positive':{'sandbox_recall':1.0,'FPR_tools':1.0,'FPR_browser_test':1.0,'F1_modelB_test':round(float(f1_score(yte,np.ones(len(yte),int))),4)},
     'modelB':{'sandbox_recall':round(float(P(sbx).mean()),4),'FPR_tools':round(float(P(tools).mean()),4),'FPR_browser_test':round(float(P(te[te.mdoh==0]).mean()),4),'F1_modelB_test':round(float(f1_score(yte,P(te))),4)}}
R['E34_baselines']=E34; print("  ",E34)
json.dump(R,open(f"{RES}/ieee_results_round6.json",'w'),indent=1,default=str); print("\nSaved.")
