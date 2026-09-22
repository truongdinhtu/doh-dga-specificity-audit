"""
ieee_access_probe2b_common.py — Probe 2b on a COMMON evaluation set.

The round-6 version of Probe 2b scored the three designs on the same folds but not on
the same flows: per-cell models abstain on a cell whose training fold holds a single
class, so design (a) was scored on 6,391 flows and designs (b)/(c) on 7,248. This script
recomputes all three on the intersection (the flows every design predicts), reports what
is dropped and why, and writes the per-flow out-of-sample predictions for inspection.
"""
import warnings; warnings.filterwarnings('ignore')
import json
import numpy as np, pandas as pd, lightgbm as lgb
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import balanced_accuracy_score, roc_auc_score, average_precision_score

ROOT="/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS"
DATA=f"{ROOT}/Code/data/csv/generated"; RES=f"{ROOT}/Code/machine_learning/results"
F6=["mean_Bpp_ab","mean_Bpp_ba","mean_pps_ab","mean_pps_ba","mean_pkts_asm","mean_bytes_asm"]

d=pd.read_csv(f"{DATA}/s2_mdoh.csv")
tools=d[d.p_type.isin(['tool_1','tool_2'])]; mal=d[d.mdoh==1]
cli=pd.concat([tools,mal],ignore_index=True)
cli['cell']=cli.p_name+'|'+cli.doh_server+'|'+cli.doh_method

parts=[]
for c,g in cli.groupby('cell'):
    nb,nm=(g.mdoh==0).sum(),(g.mdoh==1).sum()
    if nb<30 or nm<30: continue
    k=min(nb,nm); parts+=[g[g.mdoh==0].sample(n=k,random_state=42),g[g.mdoh==1].sample(n=k,random_state=42)]
sub=pd.concat(parts,ignore_index=True)
oh=pd.get_dummies(sub[['p_name','doh_server','doh_method']],dtype=float)
Xf=pd.concat([sub[F6].fillna(0),oh],axis=1); FC=list(Xf.columns)
y=sub.mdoh.astype(int); grp=sub.file_name

def lgbm(seed=42,balanced=True):
    return lgb.LGBMClassifier(objective='binary',num_leaves=63,n_estimators=300,learning_rate=0.05,
                              random_state=seed,verbosity=-1,class_weight='balanced' if balanced else None)
def fitp(Xtr,ytr,Xte,feats):
    sc=RobustScaler(quantile_range=(5,95))
    m=lgbm().fit(pd.DataFrame(sc.fit_transform(Xtr[feats]),columns=feats),ytr)
    Z=pd.DataFrame(sc.transform(Xte[feats]),columns=feats)
    return m.predict(Z),m.predict_proba(Z)[:,1]

designs=['percell','pooled','pooled_factors']
pred={k:np.full(len(sub),np.nan) for k in designs}; prob={k:np.full(len(sub),np.nan) for k in designs}
fold_of=np.full(len(sub),-1); abstain_reason={}

for fi,(tr,te) in enumerate(StratifiedGroupKFold(n_splits=5,shuffle=True,random_state=42).split(Xf,y,groups=grp)):
    fold_of[te]=fi
    p,pr=fitp(Xf.iloc[tr],y.iloc[tr],Xf.iloc[te],F6); pred['pooled'][te]=p; prob['pooled'][te]=pr
    p,pr=fitp(Xf.iloc[tr],y.iloc[tr],Xf.iloc[te],FC); pred['pooled_factors'][te]=p; prob['pooled_factors'][te]=pr
    for c in sub.cell.unique():
        trc=tr[sub.cell.values[tr]==c]; tec=te[sub.cell.values[te]==c]
        if len(tec)==0: continue
        if y.iloc[trc].nunique()<2:
            abstain_reason[f"fold{fi}|{c}"]={'n_test_flows':int(len(tec)),'n_train_flows':int(len(trc)),
                                             'train_classes':int(y.iloc[trc].nunique())}
            continue
        p,pr=fitp(Xf.iloc[trc],y.iloc[trc],Xf.iloc[tec],F6); pred['percell'][tec]=p; prob['percell'][tec]=pr

common=~np.isnan(pred['percell'])
for k in designs: common &= ~np.isnan(pred[k])
dropped=int((~common).sum())
print(f"n_total={len(sub)}  common (all three designs predict)={int(common.sum())}  dropped={dropped} ({dropped/len(sub)*100:.2f}%)")
print("Abstentions are per-cell-model only, caused by single-class training folds:")
for k,v in sorted(abstain_reason.items()): print(f"   {k:44} test_flows={v['n_test_flows']:5d} train_flows={v['n_train_flows']:6d}")
print("   total abstained flows:",sum(v['n_test_flows'] for v in abstain_reason.values()))

R={'n_population':int(len(sub)),'n_common':int(common.sum()),'n_dropped':dropped,
   'dropped_pct':round(dropped/len(sub)*100,2),'abstentions':abstain_reason,'common_set':{},'full_set':{}}
for k in designs:
    for tag,mask in [('common_set',common),('full_set',~np.isnan(pred[k]))]:
        yy=y.values[mask]; pp=pred[k][mask]; qq=prob[k][mask]
        R[tag][k]={'n':int(mask.sum()),'BA':round(float(balanced_accuracy_score(yy,pp)),4),
                   'AUC':round(float(roc_auc_score(yy,qq)),4),
                   'PR_AUC':round(float(average_precision_score(yy,qq)),4)}
print("\nOn the COMMON set (what the paper should report):")
for k in designs: print(f"   {k:16} n={R['common_set'][k]['n']} BA={R['common_set'][k]['BA']} AUC={R['common_set'][k]['AUC']} PR={R['common_set'][k]['PR_AUC']}")
print("On each design's own full set (what the paper reported before):")
for k in designs: print(f"   {k:16} n={R['full_set'][k]['n']} BA={R['full_set'][k]['BA']} AUC={R['full_set'][k]['AUC']} PR={R['full_set'][k]['PR_AUC']}")

out=sub[['file_name','p_name','doh_server','doh_method','cell','mdoh']].copy()
out['fold']=fold_of; out['in_common_set']=common
for k in designs: out[f'pred_{k}']=pred[k]; out[f'score_{k}']=prob[k]
out.to_csv(f"{RES}/probe2b_out_of_sample_predictions.csv",index=False)
json.dump(R,open(f"{RES}/ieee_results_probe2b_common.json",'w'),indent=1,default=str)
print(f"\nWrote per-flow predictions ({len(out)} rows) and summary JSON.")
