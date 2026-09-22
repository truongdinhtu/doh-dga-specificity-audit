"""
ieee_access_probe2b_audit.py — orientation / coverage / split audit for Probe 2b.

Reproduces the exact splits and fits of ieee_access_probe2b_common.py and adds, per
(fold, cell): sessions and classes in train and test, train AUC, test AUC, coverage.
Also runs an inner-validation orientation check: within each outer training fold, a
4-fold session-grouped inner CV decides whether to invert the score (never using the
outer test labels), then the chosen orientation is evaluated once on the outer test.
Writes results/ieee_results_probe2b_audit.json and results/probe2b_audit_by_fold_cell.csv.
"""
import warnings; warnings.filterwarnings('ignore')
import json, numpy as np, pandas as pd, lightgbm as lgb
from sklearn.model_selection import StratifiedGroupKFold, GroupKFold
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import balanced_accuracy_score, roc_auc_score

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
X=sub[F6].fillna(0); y=sub.mdoh.astype(int); grp=sub.file_name

def lgbm(seed=42):
    return lgb.LGBMClassifier(objective='binary',num_leaves=63,n_estimators=300,learning_rate=0.05,
                              random_state=seed,verbosity=-1,class_weight='balanced')
def fit(Xtr,ytr):
    sc=RobustScaler(quantile_range=(5,95)); m=lgbm().fit(sc.fit_transform(Xtr),ytr); return sc,m
def score(sc,m,Xe):
    assert list(m.classes_)==[0,1], m.classes_
    return m.predict_proba(sc.transform(Xe))[:,1]
def auc(yy,ss):
    return float(roc_auc_score(yy,ss)) if len(np.unique(yy))==2 else np.nan

rows=[]; inner_rows=[]
outer=StratifiedGroupKFold(n_splits=5,shuffle=True,random_state=42)
pooled_pred=np.full(len(sub),np.nan); pooled_oriented=np.full(len(sub),np.nan)
for fi,(tr,te) in enumerate(outer.split(X,y,groups=grp)):
    # ---------- pooled design: train AUC, test AUC, inner-validation orientation ----------
    sc,m=fit(X.iloc[tr],y.iloc[tr])
    s_tr=score(sc,m,X.iloc[tr]); s_te=score(sc,m,X.iloc[te])
    pooled_pred[te]=s_te
    # inner grouped CV on the training fold only
    inner_s=np.full(len(tr),np.nan)
    ytr=y.iloc[tr].values; gtr=grp.iloc[tr].values; Xtr=X.iloc[tr]
    for itr,ite in GroupKFold(n_splits=4).split(Xtr,ytr,groups=gtr):
        if len(np.unique(ytr[itr]))<2: continue
        isc,im=fit(Xtr.iloc[itr],ytr[itr]); inner_s[ite]=score(isc,im,Xtr.iloc[ite])
    ok=~np.isnan(inner_s); inner_auc=auc(ytr[ok],inner_s[ok])
    invert = inner_auc<0.5
    pooled_oriented[te]= (1-s_te) if invert else s_te
    inner_rows.append(dict(fold=fi,design='pooled',inner_val_auc=round(inner_auc,4),invert_chosen=bool(invert),
                           train_auc=round(auc(ytr,s_tr),4),outer_test_auc_raw=round(auc(y.iloc[te],s_te),4),
                           outer_test_auc_after_inner_orientation=round(auc(y.iloc[te],pooled_oriented[te]),4),
                           n_train_sessions=int(pd.Series(gtr).nunique()),n_test_sessions=int(grp.iloc[te].nunique())))
    # ---------- per-cell design ----------
    for c in sorted(sub.cell.unique()):
        trc=tr[sub.cell.values[tr]==c]; tec=te[sub.cell.values[te]==c]
        if len(tec)==0: continue
        r=dict(fold=fi,cell=c,n_train=int(len(trc)),n_test=int(len(tec)),
               train_sessions_benign=int(grp.iloc[trc][y.iloc[trc]==0].nunique()),
               train_sessions_dga=int(grp.iloc[trc][y.iloc[trc]==1].nunique()),
               test_sessions_benign=int(grp.iloc[tec][y.iloc[tec]==0].nunique()),
               test_sessions_dga=int(grp.iloc[tec][y.iloc[tec]==1].nunique()),
               train_classes=int(y.iloc[trc].nunique()),test_classes=int(y.iloc[tec].nunique()))
        if r['train_classes']<2:
            r.update(covered=False,train_auc=np.nan,test_auc=np.nan,classes_ok=None)
        else:
            sc,m=fit(X.iloc[trc],y.iloc[trc])
            r.update(covered=True,classes_ok=bool(list(m.classes_)==[0,1]),
                     train_auc=round(auc(y.iloc[trc],score(sc,m,X.iloc[trc])),4),
                     test_auc=round(auc(y.iloc[tec],score(sc,m,X.iloc[tec])),4))
        rows.append(r)

R=pd.DataFrame(rows); I=pd.DataFrame(inner_rows)
# ---- common-set (6,391) restriction and session bootstrap for the oriented pooled result ----
oof=pd.read_csv(f"{RES}/probe2b_out_of_sample_predictions.csv")
assert len(oof)==len(sub)
common=oof.in_common_set.values.astype(bool)
yv=y.values; gv=grp.values
def ba_of(yy,ss): return float(balanced_accuracy_score(yy,(ss>0.5).astype(int)))
def boot(mask,B=2000,seed=42):
    rng=np.random.default_rng(seed); sess=np.unique(gv[mask]); idx_by={s_:np.where(mask&(gv==s_))[0] for s_ in sess}
    A=[];Bv=[]
    for _ in range(B):
        pick=rng.choice(sess,len(sess),replace=True); ii=np.concatenate([idx_by[s_] for s_ in pick])
        if len(np.unique(yv[ii]))<2: continue
        A.append(auc(yv[ii],pooled_oriented[ii])); Bv.append(ba_of(yv[ii],pooled_oriented[ii]))
    return [round(float(np.percentile(A,2.5)),4),round(float(np.percentile(A,97.5)),4)],[round(float(np.percentile(Bv,2.5)),4),round(float(np.percentile(Bv,97.5)),4)]
allm=np.ones(len(sub),bool)
ciA_all,ciB_all=boot(allm); ciA_c,ciB_c=boot(common)
oriented_sets={'all_7248':{'n':int(allm.sum()),'AUC_raw':round(auc(yv,pooled_pred),4),'AUC_oriented':round(auc(yv,pooled_oriented),4),'AUC_oriented_ci95_session':ciA_all,
                           'BA_oriented':round(ba_of(yv,pooled_oriented),4),'BA_oriented_ci95_session':ciB_all},
               'common_6391':{'n':int(common.sum()),'AUC_raw':round(auc(yv[common],pooled_pred[common]),4),'AUC_oriented':round(auc(yv[common],pooled_oriented[common]),4),'AUC_oriented_ci95_session':ciA_c,
                              'BA_oriented':round(ba_of(yv[common],pooled_oriented[common]),4),'BA_oriented_ci95_session':ciB_c}}
crosstab={'combos_considered':int(len(R)),'combos_with_no_test_flows':int(120-len(R)),
          'train1_test1':int(((R.train_classes==1)&(R.test_classes==1)).sum()),'train1_test2':int(((R.train_classes==1)&(R.test_classes==2)).sum()),
          'train2_test1':int(((R.train_classes==2)&(R.test_classes==1)).sum()),'train2_test2':int(((R.train_classes==2)&(R.test_classes==2)).sum()),
          'flows_train1_test1':int(R.loc[(R.train_classes==1)&(R.test_classes==1),'n_test'].sum()),'flows_train1_test2':int(R.loc[(R.train_classes==1)&(R.test_classes==2),'n_test'].sum()),
          'flows_train2_test1':int(R.loc[(R.train_classes==2)&(R.test_classes==1),'n_test'].sum()),'flows_train2_test2':int(R.loc[(R.train_classes==2)&(R.test_classes==2),'n_test'].sum())}
R.to_csv(f"{RES}/probe2b_audit_by_fold_cell.csv",index=False)
summary={
 'n_fold_cell_combos':int(len(R)),'n_covered':int(R.covered.sum()),'n_uncovered':int((~R.covered).sum()),
 'uncovered_flows':int(R.loc[~R.covered,'n_test'].sum()),
 'classes_always_[0,1]':bool(R.loc[R.covered,'classes_ok'].all()),
 'test_combos_single_class':int((R.test_classes==1).sum()),
 'test_combos_two_class_and_covered':int(((R.test_classes==2)&R.covered).sum()),
 'cells_with_any_two_class_test':int(R[(R.test_classes==2)&R.covered].cell.nunique()),
 'percell_train_auc_median':round(float(R.train_auc.median()),4),'percell_train_auc_min':round(float(R.train_auc.min()),4),
 'percell_test_auc_median':round(float(R.test_auc.median()),4),'percell_test_auc_n_below_0.5':int((R.test_auc<0.5).sum()),
 'percell_test_auc_n':int(R.test_auc.notna().sum()),
 'pooled_by_fold':I.to_dict('records'),
 'pooled_oof_auc_raw':round(auc(y,pooled_pred),4),
 'pooled_oof_auc_after_inner_orientation':round(auc(y,pooled_oriented),4),
 'pooled_oof_BA_after_inner_orientation':round(float(balanced_accuracy_score(y,(pooled_oriented>0.5).astype(int))),4),
 'oriented_by_evaluation_set':oriented_sets,'fold_cell_crosstab':crosstab,
}
json.dump(summary,open(f"{RES}/ieee_results_probe2b_audit.json",'w'),indent=1)
print(json.dumps(summary,indent=1))
