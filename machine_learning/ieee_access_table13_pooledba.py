"""
ieee_access_table13_pooledba.py — recompute the "Pooled-bal. BA" column of the
cross-detector table under the FINAL Probe 2b protocol (3-factor cells, 5-fold
session-grouped splits, scored on the common 6,391-flow set), for all ten
feature-set x model-family configurations, replacing the earlier single-factor figure.
"""
import warnings; warnings.filterwarnings('ignore')
import json
import numpy as np, pandas as pd, lightgbm as lgb
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import balanced_accuracy_score

ROOT="/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS"
DATA=f"{ROOT}/Code/data/csv/generated"; RES=f"{ROOT}/Code/machine_learning/results"
F6=["mean_Bpp_ab","mean_Bpp_ba","mean_pps_ab","mean_pps_ba","mean_pkts_asm","mean_bytes_asm"]
F18=["duration","pkts_aggr","bytes_aggr","mean_Bpp","mean_pps","mean_Bps","pkts_ab","pkts_ba","bytes_ab","bytes_ba",
     "mean_Bpp_ab","mean_Bpp_ba","mean_pps_ab","mean_pps_ba","mean_Bps_ab","mean_Bps_ba","mean_pkts_asm","mean_bytes_asm"]

d=pd.read_csv(f"{DATA}/s2_mdoh.csv")
cli=pd.concat([d[d.p_type.isin(['tool_1','tool_2'])],d[d.mdoh==1]],ignore_index=True)
cli['cell']=cli.p_name+'|'+cli.doh_server+'|'+cli.doh_method
parts=[]
for c,g in cli.groupby('cell'):
    nb,nm=(g.mdoh==0).sum(),(g.mdoh==1).sum()
    if nb<30 or nm<30: continue
    k=min(nb,nm); parts+=[g[g.mdoh==0].sample(n=k,random_state=42),g[g.mdoh==1].sample(n=k,random_state=42)]
sub=pd.concat(parts,ignore_index=True)
y=sub.mdoh.astype(int).values; grp=sub.file_name.values

# the common evaluation mask produced by ieee_access_probe2b_common.py
ref=pd.read_csv(f"{RES}/probe2b_out_of_sample_predictions.csv")
assert len(ref)==len(sub), "population changed; regenerate probe2b_out_of_sample_predictions.csv"
common=ref.in_common_set.values

def mk(name,seed=42):
    return {'LightGBM':lgb.LGBMClassifier(objective='binary',num_leaves=63,n_estimators=300,learning_rate=0.05,
                                          random_state=seed,verbosity=-1,class_weight='balanced'),
            'RandomForest':RandomForestClassifier(n_estimators=200,random_state=seed,n_jobs=-1,class_weight='balanced'),
            'ExtraTrees':ExtraTreesClassifier(n_estimators=200,random_state=seed,n_jobs=-1,class_weight='balanced'),
            'LogisticReg':LogisticRegression(max_iter=2000,random_state=seed,class_weight='balanced'),
            'kNN':KNeighborsClassifier(n_neighbors=15,n_jobs=-1)}[name]

out={}
for fs,feats in [('NetFlow-6',F6),('NetFlow-18',F18)]:
    X=sub[feats].fillna(0)
    for mdl in ['LightGBM','RandomForest','ExtraTrees','LogisticReg','kNN']:
        pred=np.full(len(sub),np.nan)
        for tr,te in StratifiedGroupKFold(n_splits=5,shuffle=True,random_state=42).split(X,y,groups=grp):
            sc=RobustScaler(quantile_range=(5,95))
            m=mk(mdl).fit(pd.DataFrame(sc.fit_transform(X.iloc[tr]),columns=feats),y[tr])
            pred[te]=m.predict(pd.DataFrame(sc.transform(X.iloc[te]),columns=feats))
        ba=balanced_accuracy_score(y[common],pred[common])
        out[f"{fs} / {mdl}"]=round(float(ba),4)
        print(f"   {fs:11}/{mdl:13} pooled-balanced BA (common set, 3-factor, grouped) = {ba:.4f}")
json.dump({'protocol':'Probe 2b design (b), 3-factor cells, 5-fold session-grouped, common 6391-flow set',
           'pooled_balanced_BA':out},
          open(f"{RES}/ieee_results_table13_pooledba.json",'w'),indent=1)
print("\nrange:",round(min(out.values()),4),"-",round(max(out.values()),4))
