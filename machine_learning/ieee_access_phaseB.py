"""
ieee_access_phaseB.py — sandbox-malware evaluation with pipeline-matched extraction.

Sandbox PCAPs re-extracted with the SAME Tranalyzer2 container/configuration as the
generated data (FDURLIMIT=180, FLOW_TIMEOUT=65), both L3 and L7 byte accounting.
The generated dataset's byte fields are L7 (verified on a generated capture).

  E26  Model-B / Model-T on tranalyzer-L7 sandbox flows (micro/macro, per family)
  E27  Exporter / byte-layer sensitivity: NetExP-L3, Tranalyzer-L3, Tranalyzer-L7
  E28  Ten detector configurations, corrected sandbox column (6 and 18 features)
  E29  Four-feature (no rate) control on corrected sandbox
"""
import warnings; warnings.filterwarnings('ignore')
import os, glob, json
import numpy as np, pandas as pd, lightgbm as lgb
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import f1_score

ROOT="/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS"
DATA=f"{ROOT}/Code/data/csv/generated"; T2=f"{ROOT}/Code/data/csv_from_pcap/malicious/HKD_tranalyzer"
NX=f"{ROOT}/Code/data/csv_from_pcap/malicious/HKD"; RES=f"{ROOT}/Code/machine_learning/results"
F6=["mean_Bpp_ab","mean_Bpp_ba","mean_pps_ab","mean_pps_ba","mean_pkts_asm","mean_bytes_asm"]
F18=["duration","pkts_aggr","bytes_aggr","mean_Bpp","mean_pps","mean_Bps","pkts_ab","pkts_ba","bytes_ab","bytes_ba",
     "mean_Bpp_ab","mean_Bpp_ba","mean_pps_ab","mean_pps_ba","mean_Bps_ab","mean_Bps_ba","mean_pkts_asm","mean_bytes_asm"]
R={}
d=pd.read_csv(f"{DATA}/s2_mdoh.csv"); br=d[d.p_type=='browser']; tools=d[d.p_type.isin(['tool_1','tool_2'])]; mal=d[d.mdoh==1]

def rd(p):
    df=pd.read_csv(p,sep='\t'); df.columns=[c.lstrip('%') for c in df.columns]; return df
def t2_flows(fam):
    l3=rd(f"{T2}/{fam}-doh-24h_L3.csv"); l7=rd(f"{T2}/{fam}-doh-24h_L7.csv")
    m=l3.merge(l7[['flowInd','dir','l7BytesSnt']],on=['flowInd','dir'])
    a=m[m.dir=='A'].set_index('flowInd'); b=m[m.dir=='B'].set_index('flowInd'); idx=a.index.intersection(b.index); a,b=a.loc[idx],b.loc[idx]
    o=pd.DataFrame({'duration':np.maximum(a.timeLast,b.timeLast)-np.minimum(a.timeFirst,b.timeFirst),
        'pkts_ab':a.pktsSnt,'pkts_ba':b.pktsSnt,'L3_ab':a.l3BytesSnt,'L3_ba':b.l3BytesSnt,'L7_ab':a.l7BytesSnt,'L7_ba':b.l7BytesSnt,'dstPort':a.dstPort})
    o['family']=fam; return o[o.dstPort==443].reset_index(drop=True)
def build(o,layer):
    Bab,Bba=o[f'{layer}_ab'],o[f'{layer}_ba']; dur=o.duration.replace(0,np.nan); pk=o.pkts_ab+o.pkts_ba; By=Bab+Bba
    f=pd.DataFrame({'duration':o.duration,'pkts_aggr':pk,'bytes_aggr':By,'mean_Bpp':By/pk,'mean_pps':pk/dur,'mean_Bps':By/dur,
        'pkts_ab':o.pkts_ab,'pkts_ba':o.pkts_ba,'bytes_ab':Bab,'bytes_ba':Bba,'mean_Bpp_ab':Bab/o.pkts_ab,'mean_Bpp_ba':Bba/o.pkts_ba,
        'mean_pps_ab':o.pkts_ab/dur,'mean_pps_ba':o.pkts_ba/dur,'mean_Bps_ab':Bab/dur,'mean_Bps_ba':Bba/dur,
        'mean_pkts_asm':o.pkts_ba/pk,'mean_bytes_asm':Bba/By,'family':o.family})
    return f.replace([np.inf,-np.inf],np.nan).dropna().reset_index(drop=True)
raw=pd.concat([t2_flows(f) for f in ['padcrypt','sisron','tinba','zloader']],ignore_index=True)
SB_L7=build(raw,'L7'); SB_L3=build(raw,'L3')
SB_L7.to_csv(f"{T2}/sandbox_tranalyzer_L7_18features.csv",index=False)
def netexp(layer):
    out=[]
    for f in sorted(glob.glob(f"{NX}/*.csv")):
        h=pd.read_csv(f); h=h[(h.dport==443)|(h.sport==443)]
        Bab=h.sum_paysize_ab+(h.sum_ip_header_len_ab+h.sum_trans_header_len_ab if layer=='L3' else 0)
        Bba=h.sum_paysize_ba+(h.sum_ip_header_len_ba+h.sum_trans_header_len_ba if layer=='L3' else 0); dur=h.duration/1e6
        o=pd.DataFrame({'mean_Bpp_ab':Bab/h.num_packets_ab,'mean_Bpp_ba':Bba/h.num_packets_ba,'mean_pps_ab':h.num_packets_ab/dur,'mean_pps_ba':h.num_packets_ba/dur,
            'mean_pkts_asm':h.num_packets_ba/(h.num_packets_ab+h.num_packets_ba),'mean_bytes_asm':Bba/(Bab+Bba)}); o['family']=os.path.basename(f).split('-')[0]; out.append(o)
    return pd.concat(out).replace([np.inf,-np.inf],np.nan).dropna().reset_index(drop=True)

def mk(name,seed=42):
    return {'LightGBM':lgb.LGBMClassifier(objective='binary',num_leaves=63,n_estimators=300,learning_rate=0.05,random_state=seed,verbosity=-1),
            'RandomForest':RandomForestClassifier(n_estimators=200,random_state=seed,n_jobs=-1),
            'ExtraTrees':ExtraTreesClassifier(n_estimators=200,random_state=seed,n_jobs=-1),
            'LogisticReg':LogisticRegression(max_iter=2000,random_state=seed),
            'kNN':KNeighborsClassifier(n_neighbors=15,n_jobs=-1)}[name]
def fit(df,feats,model='LightGBM'):
    X,y=df[feats].fillna(0),df.mdoh.astype(int)
    Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.2,stratify=y,random_state=42)
    sc=RobustScaler(quantile_range=(5,95)); m=mk(model).fit(pd.DataFrame(sc.fit_transform(Xtr),columns=feats),ytr)
    f1=f1_score(yte,m.predict(pd.DataFrame(sc.transform(Xte),columns=feats)))
    return (lambda Z: m.predict(pd.DataFrame(sc.transform(Z[feats].fillna(0)),columns=feats))),f1
def evals(P,sb):
    p=P(sb); pf=sb.assign(p=p).groupby('family').agg(n=('p','size'),recall=('p','mean'),bpp_ab=('mean_Bpp_ab','mean'),bpp_ba=('mean_Bpp_ba','mean')).round(4)
    return {'n':int(len(sb)),'micro':round(float(p.mean()),4),'macro':round(float(pf.recall.mean()),4),'per_family':pf.to_dict('index')}

dB=pd.concat([br,mal],ignore_index=True); dT=pd.concat([br,tools,mal],ignore_index=True)
PB,f1B=fit(dB,F6); PT,f1T=fit(dT,F6)
print("[E26] Model-B on tranalyzer-L7 sandbox:"); R['E26_modelB_L7']=evals(PB,SB_L7); print("  ",R['E26_modelB_L7'])
R['E26_modelT_L7']=evals(PT,SB_L7); print("   Model-T:",R['E26_modelT_L7'])
R['E26_flow_structure']={'n_bidirectional':int(len(raw)),'pkts_median':float((raw.pkts_ab+raw.pkts_ba).median()),'duration_median_s':round(float(raw.duration.median()),2),
    'per_family_n':raw.family.value_counts().to_dict()}
print("\n[E27] Exporter / layer sensitivity (Model-B):")
R['E27']={'NetExP_L3':evals(PB,netexp('L3')),'NetExP_L7':evals(PB,netexp('L7')),'Tranalyzer_L3':evals(PB,SB_L3),'Tranalyzer_L7':evals(PB,SB_L7)}
for k,v in R['E27'].items(): print(f"   {k:14} n={v['n']:5d} micro={v['micro']:.4f} macro={v['macro']:.4f}")
R['bpp_reference']={'browser':round(float(br.mean_Bpp_ab.mean()),2),'tools':round(float(tools.mean_Bpp_ab.mean()),2),'sim_dga':round(float(mal.mean_Bpp_ab.mean()),2),
    'sandbox_T2_L7':round(float(SB_L7.mean_Bpp_ab.mean()),2),'sandbox_T2_L3':round(float(SB_L3.mean_Bpp_ab.mean()),2),
    'browser_ba':round(float(br.mean_Bpp_ba.mean()),2),'sim_dga_ba':round(float(mal.mean_Bpp_ba.mean()),2),'sandbox_T2_L7_ba':round(float(SB_L7.mean_Bpp_ba.mean()),2)}
print("\n[E28] Ten configurations, corrected sandbox recall:")
R['E28']={}
for fs,feats in [('NetFlow-6',F6),('NetFlow-18',F18)]:
    for mdl in ['LightGBM','RandomForest','ExtraTrees','LogisticReg','kNN']:
        P,f1=fit(dB,feats,mdl); r=evals(P,SB_L7); R['E28'][f"{fs} / {mdl}"]={'F1':round(float(f1),4),'sandbox_micro':r['micro'],'sandbox_macro':r['macro']}
        print(f"   {fs:11}/{mdl:13} F1={f1:.4f} sandbox micro={r['micro']:.4f} macro={r['macro']:.4f}")
print("\n[E29] Four-feature (no rate) control:")
P4,f14=fit(dB,["mean_Bpp_ab","mean_Bpp_ba","mean_pkts_asm","mean_bytes_asm"]); R['E29']={'F1':round(float(f14),4)}|evals(P4,SB_L7); print("  ",R['E29']['micro'],R['E29']['macro'])
json.dump(R,open(f"{RES}/ieee_results_phaseB.json",'w'),indent=1,default=str); print("\nSaved.")
