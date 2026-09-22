"""
ieee_access_os_doh_client.py — direct test of the client-implementation confound.

One or more sessions of a Windows 11 VM with native OS-level DoH issued benign
(Tranco top-20k) and DGA (zloader/qsnatch/bazarbackdoor/flubot) lookups through the OS
resolver in randomly ordered, time-separated blocks; traffic was captured with pktmon
and extracted with the same Tranalyzer2 container (PACKETLENGTH=3 / L7 bytes,
FDURLIMIT=180, FLOW_TIMEOUT=65) as the generated dataset. Every flow is labelled by the
block time window (within its own session) that contains its first packet. Sessions are
pooled with a session-qualified block id so the block-bootstrap treats blocks from
different sessions/resolvers as distinct experimental units. Model-B (browser benign vs
simulated DGA) is then applied.

  E35  Model-B on OS-DoH-client flows: FPR (benign blocks), recall (DGA blocks, per family)
  E36  Model-T (browser + CLI tools benign vs simulated DGA) on the same flows
  E37  Feature reference: mean Bpp_ab / Bpp_ba of OS-client flows vs browser / tools / sim-DGA
  E38  Within-OS-client separability: block-grouped CV on benign vs DGA *from the same client*,
       across several estimators and with a learnability (positive) control. At this sample size
       the Model-B LightGBM configuration (min_child_samples=20) cannot split and returns a
       constant score; reporting its AUC of 0.50 as evidence of "no signal" would be an artefact.
  E39  Per-session breakdown (FPR/recall), to check the direction replicates across resolvers

Usage: python ieee_access_os_doh_client.py
(reads the SESSIONS list below; defaults to the deposited captures under
Code/data/csv_from_pcap/os_doh_client/)
"""
import warnings; warnings.filterwarnings('ignore')
import sys, os, json
import numpy as np, pandas as pd, lightgbm as lgb
from scipy.stats import beta
from sklearn.model_selection import train_test_split, StratifiedGroupKFold
from sklearn.preprocessing import RobustScaler
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import f1_score, balanced_accuracy_score, roc_auc_score

ROOT="/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS"
DATA=f"{ROOT}/Code/data/csv/generated"; RES=f"{ROOT}/Code/machine_learning/results"
OUT=f"{ROOT}/Code/data/csv_from_pcap/os_doh_client"
F6=["mean_Bpp_ab","mean_Bpp_ba","mean_pps_ab","mean_pps_ba","mean_pkts_asm","mean_bytes_asm"]
R={}
d=pd.read_csv(f"{DATA}/s2_mdoh.csv"); br=d[d.p_type=='browser']; tools=d[d.p_type.isin(['tool_1','tool_2'])]; mal=d[d.mdoh==1]

def rd(p):
    df=pd.read_csv(p,sep='\t'); df.columns=[c.lstrip('%') for c in df.columns]; return df

def t2_bidir(l7):
    a=l7[l7.dir=='A'].set_index('flowInd'); b=l7[l7.dir=='B'].set_index('flowInd')
    idx=a.index.intersection(b.index); a,b=a.loc[idx],b.loc[idx]
    o=pd.DataFrame({'flowInd':idx,'time_first':np.minimum(a.timeFirst,b.timeFirst),'time_last':np.maximum(a.timeLast,b.timeLast),
        'pkts_ab':a.pktsSnt,'pkts_ba':b.pktsSnt,'L7_ab':a.l7BytesSnt,'L7_ba':b.l7BytesSnt,
        'srcIP':a.srcIP,'dstIP':a.dstIP,'srcPort':a.srcPort,'dstPort':a.dstPort})
    o['duration']=o.time_last-o.time_first
    return o[o.dstPort==443].reset_index(drop=True), int((l7.dir=='A').sum())

def build(o):
    Bab,Bba=o.L7_ab,o.L7_ba; dur=o.duration.replace(0,np.nan); pk=o.pkts_ab+o.pkts_ba; By=Bab+Bba
    f=pd.DataFrame({'flowInd':o.flowInd,'time_first':o.time_first,'duration':o.duration,'pkts_aggr':pk,'bytes_aggr':By,
        'pkts_ab':o.pkts_ab,'pkts_ba':o.pkts_ba,'bytes_ab':Bab,'bytes_ba':Bba,
        'mean_Bpp_ab':Bab/o.pkts_ab,'mean_Bpp_ba':Bba/o.pkts_ba,'mean_pps_ab':o.pkts_ab/dur,'mean_pps_ba':o.pkts_ba/dur,
        'mean_pkts_asm':o.pkts_ba/pk,'mean_bytes_asm':Bba/By})
    return f.replace([np.inf,-np.inf],np.nan).dropna().reset_index(drop=True)

def label(f,blocks,session):
    def find(t):
        for i,b in enumerate(blocks):
            if b['t_start']<=t<=b['t_end']: return i
        return -1
    f=f.copy(); f['time_last']=f.time_first+f.duration
    f['block_local']=f.time_first.apply(find)
    n_gap=int((f.block_local<0).sum()); f=f[f.block_local>=0].copy()
    f['block_label']=f.block_local.apply(lambda i: blocks[i]['label'])
    f['label']=f.block_label.apply(lambda l: 'benign' if l=='benign' else 'dga')
    f['family']=f.block_label.apply(lambda l: l.split(':',1)[1] if ':' in l else 'benign')
    f['mdoh']=(f.label=='dga').astype(int)
    f['session']=session
    f['block']=session+'_'+f.block_local.astype(str)   # session-qualified id: distinct bootstrap unit

    # Label-purity check: does the flow's traffic extend into the NEXT block's
    # query-generation window under a DIFFERENT binary label? The OS client's persistent
    # HTTP/2 connection can outlive the 80-s inter-block gap; a flow that does so is not
    # a pure sample of the label assigned to it. Flagged (not silently dropped) so callers
    # can report both the full set and the label-pure subset.
    def next_start(i): return blocks[i+1]['t_start'] if i+1 < len(blocks) else np.inf
    def next_label(i):
        if i+1 >= len(blocks): return None
        l=blocks[i+1]['label']; return 'benign' if l=='benign' else 'dga'
    f['spills_into_next_block']=[t_last > next_start(bi) for t_last,bi in zip(f.time_last,f.block_local)]
    f['next_block_label']=[next_label(bi) for bi in f.block_local]
    f['label_contaminated']=[bool(sp) and (nl is not None) and (nl!=lab)
                              for sp,nl,lab in zip(f.spills_into_next_block,f.next_block_label,f.label)]
    return f.reset_index(drop=True), n_gap

def lgbm(seed=42): return lgb.LGBMClassifier(objective='binary',num_leaves=63,n_estimators=300,learning_rate=0.05,random_state=seed,verbosity=-1)
def fit(df,feats,seed=42):
    X,y=df[feats].fillna(0),df.mdoh.astype(int)
    Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.2,stratify=y,random_state=42)
    sc=RobustScaler(quantile_range=(5,95)); m=lgbm(seed).fit(pd.DataFrame(sc.fit_transform(Xtr),columns=feats),ytr)
    f1=f1_score(yte,m.predict(pd.DataFrame(sc.transform(Xte),columns=feats)))
    P=lambda Z: m.predict(pd.DataFrame(sc.transform(Z[feats].fillna(0)),columns=feats))
    Q=lambda Z: m.predict_proba(pd.DataFrame(sc.transform(Z[feats].fillna(0)),columns=feats))[:,1]
    return P,Q,f1

def block_boot(df,fn,n=2000,seed=0):
    # bootstrap over blocks (the experimental unit), not flows
    rng=np.random.default_rng(seed); u=np.unique(df.block.values); idx={k:np.where(df.block.values==k)[0] for k in u}; v=[]
    for _ in range(n):
        pick=rng.choice(u,len(u),replace=True); i=np.concatenate([idx[k] for k in pick])
        try: v.append(fn(df.iloc[i]))
        except Exception: pass
    return [round(float(np.percentile(v,2.5)),4),round(float(np.percentile(v,97.5)),4)]

def clopper_pearson(k,n,alpha=0.05):
    """Exact binomial CI. Flows are not independent (blocks are), so this is reported as
    the CI that would hold under the most favourable independence assumption --- an upper
    bound on precision, not a claim of it."""
    lo=0.0 if k==0 else float(beta.ppf(alpha/2,k,n-k+1))
    hi=1.0 if k==n else float(beta.ppf(1-alpha/2,k+1,n-k))
    return [round(lo,4),round(hi,4)]

def evals(P,Q,f):
    p=P(f); q=Q(f); g=f.assign(p=p,q=q)
    ben=g[g.label=='benign']; dga=g[g.label=='dga']
    per_fam=dga.groupby('family').agg(n=('p','size'),recall=('p','mean'),n_blocks=('block','nunique')).round(4)
    per_block=g.groupby(['block','block_label']).agg(n=('p','size'),pos_rate=('p','mean')).round(4).reset_index()
    return {'n_benign':int(len(ben)),'n_dga':int(len(dga)),
            'FPR_benign':round(float(ben.p.mean()),4),
            'FPR_ci95_exact':clopper_pearson(int(ben.p.sum()),len(ben)),
            'recall_dga':round(float(dga.p.mean()),4),
            'recall_ci95_exact':clopper_pearson(int(dga.p.sum()),len(dga)),
            'n_benign_blocks':int(ben.block.nunique()),'n_dga_blocks':int(dga.block.nunique()),
            'recall_macro_family':round(float(per_fam.recall.mean()),4),'per_family':per_fam.to_dict('index'),
            'AUC_benign_vs_dga_within_client':round(float(roc_auc_score(g.mdoh,g.q)),4) if g.mdoh.nunique()==2 else None,
            'per_block':per_block.to_dict('records')}

# session_id -> (t2 L7 csv, blocks json, resolver label)
SESSIONS=[
    ('cloudflare_1',f"{OUT}/tranalyzer/doh_capture_20260920_014023_L7.csv",f"{OUT}/pcap/blocks_20260920_024034.json"),
    ('google_1',    f"{OUT}/tranalyzer/doh_capture_20260920_195435_google_L7.csv",f"{OUT}/pcap/blocks_20260920_205445.json"),
    ('quad9_1',     f"{OUT}/tranalyzer/doh_capture_20260921_211840_L7.csv",f"{OUT}/pcap/blocks_20260921_221858.json"),
]

if __name__=='__main__':
    parts=[]; data_meta={}
    for sid,t2csv,blocks_json in SESSIONS:
        meta=json.load(open(blocks_json)); blocks=meta['blocks']
        raw,n_dirA=t2_bidir(rd(t2csv)); feat=build(raw); part,n_gap=label(feat,blocks,sid)
        parts.append(part)
        data_meta[sid]={'capture':os.path.basename(t2csv),'n_dirA_rows':n_dirA,'n_bidirectional_443':int(len(raw)),
            'n_after_feature_dropna':int(len(feat)),'n_in_gap_dropped':n_gap,'n_labelled':int(len(part)),
            'n_blocks':len(blocks),'order':meta['order'],'per_block_label_n':part.groupby('block_label').size().to_dict(),
            'lookups_per_block':[b['n_lookups'] for b in blocks]}
        print(f"[{sid}]",json.dumps(data_meta[sid],indent=1,default=str))
    OS=pd.concat(parts,ignore_index=True)
    os.makedirs(OUT,exist_ok=True); OS.to_csv(f"{OUT}/os_doh_client_L7_flows.csv",index=False)
    n_contam=int(OS.label_contaminated.sum())
    OS_pure=OS[~OS.label_contaminated].reset_index(drop=True)
    print(f"\n[label purity] {n_contam}/{len(OS)} flows extend into the next block's window "
          f"under a DIFFERENT binary label and are excluded from the primary analysis "
          f"(contaminated flowInd/session: "
          f"{OS[OS.label_contaminated][['session','flowInd']].to_dict('records')}). "
          f"{len(OS_pure)} flows remain.")
    R['data']={'sessions':data_meta,'n_sessions':len(SESSIONS),'n_labelled_total':int(len(OS)),
        'n_label_contaminated':n_contam,'n_label_pure':int(len(OS_pure)),
        'per_session_label_n':OS.groupby(['session','label']).size().unstack(fill_value=0).to_dict('index'),
        'flow_pkts_median':float(OS.pkts_aggr.median()),'flow_duration_median_s':round(float(OS.duration.median()),2)}
    print("\n[data pooled]",json.dumps(R['data'],indent=1,default=str))
    OS=OS_pure   # primary analysis uses only label-pure flows from here on

    dB=pd.concat([br,mal],ignore_index=True); dT=pd.concat([br,tools,mal],ignore_index=True)
    PB,QB,f1B=fit(dB,F6); PT,QT,f1T=fit(dT,F6)
    # per-flow prediction manifest (all 478 flows; label-pure flag included) for Table 12
    import hashlib
    ALL=pd.concat(parts,ignore_index=True)
    mani=ALL[['session','block','flowInd','label','family','block_label','time_first','time_last','label_contaminated']].copy()
    mani['resolver']=mani.session.str.replace(r'_\d+$','',regex=True)
    mani['score_modelB']=QB(ALL); mani['pred_modelB']=PB(ALL).astype(int)
    mani['score_modelT']=QT(ALL); mani['pred_modelT']=PT(ALL).astype(int)
    mani['exclusion_reason']=mani.label_contaminated.map({True:'overlaps_block_of_other_label',False:''})
    mani['model_hash_modelB']=hashlib.sha256(pd.util.hash_pandas_object(pd.Series(QB(dB.head(2000)))).values.tobytes()).hexdigest()[:16]
    mani.to_csv(f"{OUT}/os_doh_client_predictions_manifest.csv",index=False)
    print(f"[manifest] wrote {len(mani)} rows -> {OUT}/os_doh_client_predictions_manifest.csv")
    print("\n[E35] Model-B on OS-DoH-client flows (F1 on own test set = %.4f)"%f1B); R['E35_modelB']=evals(PB,QB,OS)
    for k in ['n_benign','n_dga','FPR_benign','FPR_ci95_exact','recall_dga','recall_ci95_exact','recall_macro_family','AUC_benign_vs_dga_within_client']: print(f"   {k:32} {R['E35_modelB'][k]}")
    print("   per family:",R['E35_modelB']['per_family'])
    print("\n[E36] Model-T on OS-DoH-client flows (F1 = %.4f)"%f1T); R['E36_modelT']=evals(PT,QT,OS)
    for k in ['FPR_benign','FPR_ci95_exact','recall_dga','recall_ci95_exact','recall_macro_family','AUC_benign_vs_dga_within_client']: print(f"   {k:32} {R['E36_modelT'][k]}")

    # seed robustness for Model-B
    R['E35_seeds']={}
    for s in [1,2,3,4,5]:
        P,Q,_=fit(dB,F6,seed=s); e=evals(P,Q,OS); R['E35_seeds'][s]={'FPR_benign':e['FPR_benign'],'recall_dga':e['recall_dga']}
    print("   Model-B seeds:",R['E35_seeds'])

    print("\n[E37] Feature reference (mean over flows):")
    ref={}
    for nm,g in [('browser',br),('tools',tools),('sim_dga',mal),('os_client_benign',OS[OS.label=='benign']),('os_client_dga',OS[OS.label=='dga'])]:
        ref[nm]={c:round(float(g[c].mean()),3) for c in F6}|{'median_Bpp_ab':round(float(g.mean_Bpp_ab.median()),2),'median_Bpp_ba':round(float(g.mean_Bpp_ba.median()),2),'n':int(len(g))}
        print(f"   {nm:18} Bpp_ab={ref[nm]['mean_Bpp_ab']:8.2f} Bpp_ba={ref[nm]['mean_Bpp_ba']:8.2f} pps_ab={ref[nm]['mean_pps_ab']:7.3f} pkts_asm={ref[nm]['mean_pkts_asm']:.3f} n={ref[nm]['n']}")
    R['E37_feature_reference']=ref

    print("\n[E38] Within-OS-client separability (block-grouped 4-fold CV, benign vs DGA from the same client)")
    print("      Reported across estimators, with a learnability control, because n is small:")
    X,y,g=OS[F6].fillna(0).values,OS.mdoh.values,OS.block.values

    def cv_est(make,Xm,ym,gm):
        """Returns pooled/fold AUC, BA, and diagnostics that reveal a model which never split."""
        pred=np.full(len(ym),np.nan); prob=np.full(len(ym),np.nan); fold_auc=[]; splits=[]
        for tr,te in StratifiedGroupKFold(n_splits=4,shuffle=True,random_state=42).split(Xm,ym,groups=gm):
            sc=RobustScaler(quantile_range=(5,95)); Xtr=sc.fit_transform(Xm[tr]); Xte=sc.transform(Xm[te])
            m=make().fit(Xtr,ym[tr]); q=m.predict_proba(Xte)[:,1]
            pred[te]=m.predict(Xte); prob[te]=q
            if len(np.unique(ym[te]))==2: fold_auc.append(roc_auc_score(ym[te],q))
            if hasattr(m,'booster_'):
                splits.append(sum(t['num_leaves']-1 for t in m.booster_.dump_model()['tree_info']))
            elif hasattr(m,'tree_'): splits.append(int(m.tree_.node_count//2))
            else: splits.append(None)
        return {'AUC_pooled':round(float(roc_auc_score(ym,prob)),4),
                'AUC_fold_mean':round(float(np.mean(fold_auc)),4) if fold_auc else None,
                'BA':round(float(balanced_accuracy_score(ym,pred)),4),
                'F1':round(float(f1_score(ym,pred)),4),
                'n_distinct_scores':int(len(np.unique(prob.round(6)))),
                'total_splits_per_fold':splits}

    ESTIMATORS={
        'LogReg_C1':      lambda: LogisticRegression(C=1.0,max_iter=2000),
        'LogReg_C0.1':    lambda: LogisticRegression(C=0.1,max_iter=2000),
        'Tree_d2_leaf4':  lambda: DecisionTreeClassifier(max_depth=2,min_samples_leaf=4,random_state=42),
        'LGBM_small':     lambda: lgb.LGBMClassifier(objective='binary',num_leaves=4,min_child_samples=4,
                                                     n_estimators=50,learning_rate=0.1,random_state=42,verbosity=-1),
        'LGBM_paper_cfg': lgbm,   # the Model-B configuration; retained to document that it cannot fit n of this size
    }
    E38={'n':int(len(OS)),'n_train_per_fold':int(round(len(OS)*0.75)),'estimators':{}}
    for nm,mk in ESTIMATORS.items():
        E38['estimators'][nm]=cv_est(mk,X,y,g)
        e=E38['estimators'][nm]
        print(f"   {nm:16} AUC_pooled={e['AUC_pooled']:.3f} AUC_fold={e['AUC_fold_mean']} BA={e['BA']:.3f} "
              f"distinct_scores={e['n_distinct_scores']} splits/fold={e['total_splits_per_fold']}")

    # Learnability control: inject one obviously separable feature. An estimator that cannot
    # recover THIS has no power on this sample size, so its chance-level score is uninformative.
    rng=np.random.default_rng(0)
    Xc=np.column_stack([X, y*2.0+rng.normal(0,0.5,len(y))])
    E38['positive_control']={nm:cv_est(mk,Xc,y,g)['AUC_pooled'] for nm,mk in ESTIMATORS.items()}
    print("   positive control (injected separable feature), AUC by estimator:")
    for nm,v in E38['positive_control'].items():
        flag='  <-- NO POWER at this n' if v<=0.55 else ''
        print(f"     {nm:16} {v:.3f}{flag}")

    aucs=[e['AUC_pooled'] for nm,e in E38['estimators'].items() if E38['positive_control'][nm]>0.55]
    E38['informative_estimators_AUC_range']=[round(min(aucs),4),round(max(aucs),4)] if aucs else None
    E38['interpretation']=('At n=%d the estimate is unstable across estimators (AUC %s); the sample is too small '
                           'to establish either the presence or the absence of a benign-vs-DGA signal within this client. '
                           'The Model-B configuration produces a constant prediction at this sample size (zero splits) '
                           'and is therefore excluded from the range.'%(len(OS),E38['informative_estimators_AUC_range']))
    print("   informative-estimator AUC range:",E38['informative_estimators_AUC_range'])
    R['E38_within_client']=E38

    print("\n[E39] Per-session breakdown (Model-B), checking the direction replicates across resolvers:")
    R['E39_per_session']={}
    for sid,_,_ in SESSIONS:
        s=OS[OS.session==sid]
        if len(s)==0: continue
        e=evals(PB,QB,s)
        R['E39_per_session'][sid]={'n_benign':e['n_benign'],'n_dga':e['n_dga'],'FPR_benign':e['FPR_benign'],'recall_dga':e['recall_dga']}
        print(f"   {sid:14} n_benign={e['n_benign']:3d} n_dga={e['n_dga']:3d} FPR={e['FPR_benign']:.4f} recall={e['recall_dga']:.4f}")

    json.dump(R,open(f"{RES}/ieee_results_os_doh_client.json",'w'),indent=1,default=str); print("\nSaved.")
